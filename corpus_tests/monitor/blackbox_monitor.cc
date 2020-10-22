// Copyright 2020 Google LLC
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

#include "corpus_tests/monitor/blackbox_monitor.h"

#include <iostream>
#include <optional>

#include "glog/logging.h"
#include "src/cbor_builders.h"
#include "src/crypto_utility.h"
#include "src/fido2_commands.h"

namespace corpus_tests {

// Default pin = 1234
const cbor::Value::BinaryValue kDefaultPin = {0x31, 0x32, 0x33, 0x34};
constexpr size_t kPinByteLength = 64;

void BlackboxMonitor::ComputeSharedSecret() {
  fido2_tests::AuthenticatorClientPinCborBuilder key_agreement_builder;
  key_agreement_builder.AddDefaultsForGetKeyAgreement();
  absl::variant<cbor::Value, fido2_tests::Status> key_response =
      fido2_tests::fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, key_agreement_builder.GetCbor());

  CHECK(!absl::holds_alternative<fido2_tests::Status>(key_response))
      << "Key agreement failed - returned status code "
      << StatusToString(absl::get<fido2_tests::Status>(key_response));

  const auto& key_agreement_map = absl::get<cbor::Value>(key_response).GetMap();
  auto map_iter = key_agreement_map.find(cbor::Value(1));
  shared_secret_ = fido2_tests::crypto_utility::CompleteEcdhHandshake(
      map_iter->second.GetMap(), &platform_cose_key_);
}

void BlackboxMonitor::SetDefaultPin() {
  CHECK(kDefaultPin.size() >= 4 && kDefaultPin.size() <= 63)
      << "PIN requirements not fulfilled - TEST SUITE BUG";
  cbor::Value::BinaryValue new_padded_pin(kPinByteLength, 0);
  std::copy(kDefaultPin.begin(), kDefaultPin.end(), new_padded_pin.begin());
  cbor::Value::BinaryValue new_pin_enc =
      fido2_tests::crypto_utility::Aes256CbcEncrypt(shared_secret_,
                                                    new_padded_pin);
  cbor::Value::BinaryValue pin_auth =
      fido2_tests::crypto_utility::LeftHmacSha256(shared_secret_, new_pin_enc);

  fido2_tests::AuthenticatorClientPinCborBuilder set_pin_builder;
  set_pin_builder.AddDefaultsForSetPin(platform_cose_key_, pin_auth,
                                       new_pin_enc);
  absl::variant<cbor::Value, fido2_tests::Status> set_pin_response =
      fido2_tests::fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, set_pin_builder.GetCbor());
  CHECK(!absl::holds_alternative<fido2_tests::Status>(set_pin_response))
      << "Set default pin failed - returned status code "
      << StatusToString(absl::get<fido2_tests::Status>(set_pin_response));
}

std::optional<cbor::Value::BinaryValue> BlackboxMonitor::GetPinToken() {
  fido2_tests::AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc =
      fido2_tests::crypto_utility::Aes256CbcEncrypt(
          shared_secret_,
          fido2_tests::crypto_utility::LeftSha256Hash(kDefaultPin));
  pin_token_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(platform_cose_key_,
                                                            pin_hash_enc);
  absl::variant<cbor::Value, fido2_tests::Status> pin_token_response =
      fido2_tests::fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, pin_token_builder.GetCbor());

  if (absl::holds_alternative<fido2_tests::Status>(pin_token_response)) {
    return {};
  }
  const auto& pin_token_map =
      absl::get<cbor::Value>(pin_token_response).GetMap();
  auto map_iter = pin_token_map.find(cbor::Value(2));
  cbor::Value::BinaryValue encrypted_token = map_iter->second.GetBytestring();
  return fido2_tests::crypto_utility::Aes256CbcDecrypt(shared_secret_,
                                                       encrypted_token);
}

BlackboxMonitor::BlackboxMonitor(fido2_tests::DeviceInterface* device,
                                 fido2_tests::DeviceTracker* device_tracker)
    : device_(device), device_tracker_(device_tracker) {
  initial_pin_token_ = cbor::Value::BinaryValue();
  shared_secret_ = cbor::Value::BinaryValue();
  platform_cose_key_ = cbor::Value::MapValue();
}

bool BlackboxMonitor::Attach() {
  ComputeSharedSecret();
  SetDefaultPin();
  std::optional<cbor::Value::BinaryValue> pin_token = GetPinToken();
  if (!pin_token.has_value()) {
    return false;
  }
  initial_pin_token_ = pin_token.value();
  return true;
}

bool BlackboxMonitor::DeviceCrashed() {
  std::optional<cbor::Value::BinaryValue> pin_token = GetPinToken();
  return !pin_token.has_value() || pin_token.value() != initial_pin_token_;
}

}  // namespace corpus_tests