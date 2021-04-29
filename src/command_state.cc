// Copyright 2020-2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/command_state.h"

#include <iostream>

#include "absl/strings/escaping.h"
#include "absl/time/clock.h"
#include "absl/types/variant.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/crypto_utility.h"
#include "src/fido2_commands.h"

namespace fido2_tests {
namespace {
constexpr size_t kPinByteLength = 64;
constexpr int kResetRetries = 3;

// Returns a PIN of the given length. This PIN is supposed to be used as the
// default throughout.
cbor::Value::BinaryValue DefaultPin(size_t pin_length) {
  cbor::Value::BinaryValue pin;
  for (size_t i = 0; i < pin_length; ++i) {
    pin.push_back('1' + i);
  }
  return pin;
}
}  // namespace

CommandState::CommandState(DeviceInterface* device,
                           DeviceTracker* device_tracker)
    : device_(device), device_tracker_(device_tracker) {
  Reset();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device_, device_tracker_);
  device_tracker_->AssertResponse(response, "GetInfo");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  if (auto map_iter = decoded_map.find(CborInt(InfoMember::kAaguid));
      map_iter != decoded_map.end()) {
    const cbor::Value::BinaryValue& aaguid_bytes =
        map_iter->second.GetBytestring();
    std::string aaguid_string(aaguid_bytes.begin(), aaguid_bytes.end());
    device_tracker->SetAaguid(absl::BytesToHexString(aaguid_string));
  }
}

void CommandState::PromptReplugAndInit() {
  std::cout << "Please replug the device, then hit enter." << std::endl;
  std::cin.ignore();
  CHECK(fido2_tests::Status::kErrNone == device_->Init())
      << "CTAPHID initialization failed";

  platform_cose_key_ = cbor::Value::MapValue();
  shared_secret_ = cbor::Value::BinaryValue();
  auth_token_ = cbor::Value::BinaryValue();
}

void CommandState::Reset() {
  std::cout << "You have 10 seconds for the next touch after pressing enter.\n";
  PromptReplugAndInit();
  absl::variant<cbor::Value, Status> response;
  for (int i = 0; i < kResetRetries; ++i) {
    // Linear increase of waiting time by using the iteration index as a
    // multiplier. This has the nice advantage of not waiting on the first
    // iteration.
    absl::SleepFor(absl::Milliseconds(100) * i);
    response = fido2_commands::ResetPositiveTest(device_);
    if (device_tracker_->CheckStatus(response)) {
      break;
    }
  }
  device_tracker_->AssertResponse(response, "Reset");

  platform_cose_key_ = cbor::Value::MapValue();
  shared_secret_ = cbor::Value::BinaryValue();
  pin_utf8_ = cbor::Value::BinaryValue();
  auth_token_ = cbor::Value::BinaryValue();
}

void CommandState::Prepare(bool set_uv) {
  if (set_uv) {
    device_tracker_->AssertResponse(GetAuthToken(), "refresh auth token");
  } else {
    if (!pin_utf8_.empty()) {
      Reset();
    }
  }
}

absl::variant<cbor::Value, Status> CommandState::MakeTestCredential(
    std::string rp_id, bool use_resident_key) {
  MakeCredentialCborBuilder test_builder;
  test_builder.AddDefaultsForRequiredFields(std::move(rp_id));
  test_builder.SetResidentKeyOptions(use_resident_key);
  if (!auth_token_.empty()) {
    test_builder.SetDefaultPinUvAuthParam(auth_token_);
    test_builder.SetDefaultPinUvAuthProtocol();
  }

  return fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                    test_builder.GetCbor());
}

absl::variant<cbor::Value, Status> CommandState::GetKeyAgreementValue() {
  AuthenticatorClientPinCborBuilder key_agreement_builder;
  key_agreement_builder.AddDefaultsForGetKeyAgreement();
  return fido2_commands::AuthenticatorClientPinPositiveTest(
      device_, device_tracker_, key_agreement_builder.GetCbor());
}

Status CommandState::ComputeSharedSecret() {
  absl::variant<cbor::Value, Status> key_response = GetKeyAgreementValue();
  if (absl::holds_alternative<Status>(key_response)) {
    device_tracker_->AddObservation("GetKeyAgreement failed");
    return absl::get<Status>(key_response);
  }

  const auto& key_agreement_map = absl::get<cbor::Value>(key_response).GetMap();
  auto map_iter =
      key_agreement_map.find(CborInt(ClientPinResponse::kKeyAgreement));
  shared_secret_ = crypto_utility::CompleteEcdhHandshake(
      map_iter->second.GetMap(), &platform_cose_key_);
  return Status::kErrNone;
}

Status CommandState::SetPin(const cbor::Value::BinaryValue& new_pin_utf8) {
  if (platform_cose_key_.empty() || shared_secret_.empty()) {
    OK_OR_RETURN(ComputeSharedSecret());
  }
  if (!pin_utf8_.empty()) {
    return Status::kErrNone;
  }
  CHECK(new_pin_utf8.size() >= 4 && new_pin_utf8.size() <= 63)
      << "PIN requirements not fulfilled - TEST SUITE BUG";

  cbor::Value::BinaryValue new_padded_pin(kPinByteLength, 0);
  std::copy(new_pin_utf8.begin(), new_pin_utf8.end(), new_padded_pin.begin());
  cbor::Value::BinaryValue new_pin_enc =
      crypto_utility::Aes256CbcEncrypt(shared_secret_, new_padded_pin);
  cbor::Value::BinaryValue pin_auth =
      crypto_utility::LeftHmacSha256(shared_secret_, new_pin_enc);

  AuthenticatorClientPinCborBuilder set_pin_builder;
  set_pin_builder.AddDefaultsForSetPin(platform_cose_key_, pin_auth,
                                       new_pin_enc);
  absl::variant<cbor::Value, Status> set_pin_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, set_pin_builder.GetCbor());
  if (absl::holds_alternative<Status>(set_pin_response)) {
    device_tracker_->AddObservation("SetPin failed.");
    // Failed PIN checks reset the key agreement, keep the state consistent.
    OK_OR_RETURN(ComputeSharedSecret());
    return absl::get<Status>(set_pin_response);
  } else {
    pin_utf8_ = new_pin_utf8;
    return Status::kErrNone;
  }
}

Status CommandState::SetPin() {
  return SetPin(DefaultPin(device_tracker_->GetMinPinLength()));
}

Status CommandState::AttemptSetPin(
    const cbor::Value::BinaryValue& new_padded_pin) {
  if (platform_cose_key_.empty() || shared_secret_.empty()) {
    OK_OR_RETURN(ComputeSharedSecret());
  }

  cbor::Value::BinaryValue new_pin_enc =
      crypto_utility::Aes256CbcEncrypt(shared_secret_, new_padded_pin);
  cbor::Value::BinaryValue pin_auth =
      crypto_utility::LeftHmacSha256(shared_secret_, new_pin_enc);

  AuthenticatorClientPinCborBuilder set_pin_builder;
  set_pin_builder.AddDefaultsForSetPin(platform_cose_key_, pin_auth,
                                       new_pin_enc);
  return fido2_commands::AuthenticatorClientPinNegativeTest(
      device_, set_pin_builder.GetCbor(), false);
}

Status CommandState::ChangePin(const cbor::Value::BinaryValue& new_pin_utf8) {
  OK_OR_RETURN(SetPin());
  CHECK(new_pin_utf8.size() >= 4 && new_pin_utf8.size() <= 63)
      << "PIN requirements not fulfilled - TEST SUITE BUG";

  cbor::Value::BinaryValue new_padded_pin(kPinByteLength, 0);
  std::copy(new_pin_utf8.begin(), new_pin_utf8.end(), new_padded_pin.begin());
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  cbor::Value::BinaryValue new_pin_enc =
      crypto_utility::Aes256CbcEncrypt(shared_secret_, new_padded_pin);
  cbor::Value::BinaryValue auth_data(new_pin_enc);
  auth_data.insert(auth_data.end(), pin_hash_enc.begin(), pin_hash_enc.end());
  cbor::Value::BinaryValue pin_auth =
      crypto_utility::LeftHmacSha256(shared_secret_, auth_data);

  AuthenticatorClientPinCborBuilder change_pin_builder;
  change_pin_builder.AddDefaultsForChangePin(platform_cose_key_, pin_auth,
                                             new_pin_enc, pin_hash_enc);
  absl::variant<cbor::Value, Status> change_pin_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, change_pin_builder.GetCbor());

  if (absl::holds_alternative<Status>(change_pin_response)) {
    device_tracker_->AddObservation("ChangePin failed.");
    // Failed PIN checks reset the key agreement, keep the state consistent.
    OK_OR_RETURN(ComputeSharedSecret());
    return absl::get<Status>(change_pin_response);
  } else {
    pin_utf8_ = new_pin_utf8;
    return Status::kErrNone;
  }
}

Status CommandState::AttemptChangePin(
    const cbor::Value::BinaryValue& new_padded_pin) {
  OK_OR_RETURN(SetPin());

  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  cbor::Value::BinaryValue new_pin_enc =
      crypto_utility::Aes256CbcEncrypt(shared_secret_, new_padded_pin);
  cbor::Value::BinaryValue auth_data(new_pin_enc);
  auth_data.insert(auth_data.end(), pin_hash_enc.begin(), pin_hash_enc.end());
  cbor::Value::BinaryValue pin_auth =
      crypto_utility::LeftHmacSha256(shared_secret_, auth_data);

  AuthenticatorClientPinCborBuilder change_pin_builder;
  change_pin_builder.AddDefaultsForChangePin(platform_cose_key_, pin_auth,
                                             new_pin_enc, pin_hash_enc);
  Status returned_status = fido2_commands::AuthenticatorClientPinNegativeTest(
      device_, change_pin_builder.GetCbor(), false);
  // Failed PIN checks reset the key agreement, keep the state consistent.
  OK_OR_RETURN(ComputeSharedSecret());
  return returned_status;
}

Status CommandState::GetAuthToken(bool set_pin_if_necessary) {
  if (set_pin_if_necessary) {
    OK_OR_RETURN(SetPin());
  }

  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  pin_token_builder.AddDefaultsForGetPinToken(platform_cose_key_, pin_hash_enc);
  absl::variant<cbor::Value, Status> pin_token_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, pin_token_builder.GetCbor());

  if (absl::holds_alternative<Status>(pin_token_response)) {
    if (set_pin_if_necessary) {
      // This is acceptable behaviour if not set up properly.
      device_tracker_->AddObservation("GetAuthToken failed.");
    }
    // Failed PIN checks reset the key agreement, keep the state consistent.
    auth_token_ = cbor::Value::BinaryValue();
    OK_OR_RETURN(ComputeSharedSecret());
    return absl::get<Status>(pin_token_response);
  } else {
    const auto& pin_token_map =
        absl::get<cbor::Value>(pin_token_response).GetMap();
    auto map_iter =
        pin_token_map.find(CborInt(ClientPinResponse::kPinUvAuthToken));
    cbor::Value::BinaryValue encrypted_token = map_iter->second.GetBytestring();
    auth_token_ =
        crypto_utility::Aes256CbcDecrypt(shared_secret_, encrypted_token);
    return Status::kErrNone;
  }
}

Status CommandState::AttemptGetAuthToken(
    const cbor::Value::BinaryValue& pin_utf8, bool redo_key_agreement) {
  OK_OR_RETURN(SetPin());

  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8));
  pin_token_builder.AddDefaultsForGetPinToken(platform_cose_key_, pin_hash_enc);
  Status returned_status = fido2_commands::AuthenticatorClientPinNegativeTest(
      device_, pin_token_builder.GetCbor(), false);
  if (redo_key_agreement) {
    // Failed PIN checks reset the key agreement, keep the state consistent.
    OK_OR_RETURN(ComputeSharedSecret());
  }
  return returned_status;
}

Status CommandState::AttemptGetAuthToken() {
  return AttemptGetAuthToken(DefaultPin(device_tracker_->GetMinPinLength()));
}

cbor::Value::BinaryValue CommandState::GetCurrentAuthToken() {
  return auth_token_;
}

}  // namespace fido2_tests

