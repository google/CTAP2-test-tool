// Copyright 2019 Google LLC
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

#include "src/tests/test_series.h"

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "glog/logging.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/crypto_utility.h"
#include "src/fido2_commands.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {
namespace {
constexpr size_t kPinByteLength = 64;

std::string CborTypeToString(cbor::Value::Type cbor_type) {
  switch (cbor_type) {
    case cbor::Value::Type::UNSIGNED:
      return "unsigned";
    case cbor::Value::Type::NEGATIVE:
      return "negative";
    case cbor::Value::Type::BYTE_STRING:
      return "byte string";
    case cbor::Value::Type::STRING:
      return "text string";
    case cbor::Value::Type::ARRAY:
      return "array";
    case cbor::Value::Type::MAP:
      return "map";
    case cbor::Value::Type::TAG:
      return "tag";
    case cbor::Value::Type::SIMPLE_VALUE:
      return "simple value";
    case cbor::Value::Type::NONE:
      return "none";
  }
}

// Special behavior is only implemented for strings and integers, because this
// function is called on map keys and no other types are expected.
std::string CborToString(const std::string& name_prefix,
                         const cbor::Value& cbor_value) {
  switch (cbor_value.type()) {
    // Both integer types have the same behavior.
    case cbor::Value::Type::UNSIGNED:
    case cbor::Value::Type::NEGATIVE:
      return absl::StrCat(name_prefix, " \"", cbor_value.GetInteger(), "\"");
    case cbor::Value::Type::STRING:
      return absl::StrCat(name_prefix, " \"", cbor_value.GetString(), "\"");
    default:
      return name_prefix;
  }
}
}  // namespace

namespace test_helpers {

// Asserts a general condition, exits on failure.
void AssertCondition(bool condition, const std::string& test_name) {
  CHECK(condition) << "Failed critical test: " << test_name;
}

// As above, but asserts the success of an executed command.
void AssertResponse(const absl::variant<cbor::Value, Status>& returned_variant,
                    const std::string& test_name) {
  CHECK(!absl::holds_alternative<Status>(returned_variant))
      << "Failed critical test: " << test_name << " - returned status code "
      << StatusToString(absl::get<Status>(returned_variant));
}

// Extracts the credential ID from an authenticator data structure[1].
// [1] https://www.w3.org/TR/webauthn/#sec-authenticator-data
cbor::Value::BinaryValue ExtractCredentialId(const cbor::Value& response) {
  const auto& decoded_map = response.GetMap();
  auto map_iter = decoded_map.find(cbor::Value(2));
  CHECK(map_iter != decoded_map.end()) << "key 2 for authData is not contained";
  CHECK(map_iter->second.is_bytestring())
      << "authData entry is not a bytestring";
  cbor::Value::BinaryValue auth_data = map_iter->second.GetBytestring();
  constexpr size_t length_offset = 32 /* RP ID hash */ + 1 /* flags */ +
                                   4 /* signature counter */ + 16 /* AAGUID */;
  CHECK_GE(auth_data.size(), length_offset + 2)
      << "authData does not fit the attested credential data length";
  CHECK((auth_data[32] & 0x40) != 0)
      << "flags not indicating that attested credential data is included";
  size_t credential_id_length =
      256u * auth_data[length_offset] + auth_data[length_offset + 1];
  CHECK_GE(auth_data.size(), length_offset + 2 + credential_id_length)
      << "authData does not fit the attested credential ID";
  return cbor::Value::BinaryValue(
      auth_data.begin() + length_offset + 2,
      auth_data.begin() + length_offset + 2 + credential_id_length);
}

// Extracts the PIN retries from an authenticator client PIN response.
int ExtractPinRetries(const cbor::Value& response) {
  const auto& decoded_map = response.GetMap();
  auto map_iter = decoded_map.find(cbor::Value(3));
  CHECK(map_iter != decoded_map.end())
      << "key 3 for pinRetries is not contained";
  CHECK(map_iter->second.is_integer()) << "pinRetries entry is not an integer";
  return map_iter->second.GetInteger();
}

void PrintByteVector(const cbor::Value::BinaryValue& vec) {
  std::cout << "0x";
  for (uint8_t c : vec) {
    std::cout << absl::StrCat(absl::Hex(c, absl::kZeroPad2));
  }
  std::cout << std::endl;
}

void PrintNoTouchPrompt() {
  std::cout << "===========================================================\n"
            << "The next test checks if timeouts work properly. This time,\n"
            << "please do not touch the key, regardless all prompts, for 30\n"
            << "seconds. Check if you see a flashing LED on the device.\n"
            << "===========================================================\n";
}

}  // namespace test_helpers

TestSeries::TestSeries(DeviceInterface* device, DeviceTracker* device_tracker)
    : device_(device),
      device_tracker_(device_tracker),
      cose_key_example_(crypto_utility::GenerateExampleEcdhCoseKey()),
      bad_pin_({0x66, 0x61, 0x6B, 0x65}) {
  cbor::Value::ArrayValue array_example;
  array_example.push_back(cbor::Value(42));
  cbor::Value::MapValue map_example;
  map_example[cbor::Value(42)] = cbor::Value(42);
  type_examples_[cbor::Value::Type::UNSIGNED] = cbor::Value(42);
  type_examples_[cbor::Value::Type::NEGATIVE] = cbor::Value(-42);
  type_examples_[cbor::Value::Type::BYTE_STRING] =
      cbor::Value(cbor::Value::BinaryValue({0x42}));
  type_examples_[cbor::Value::Type::STRING] = cbor::Value("42");
  type_examples_[cbor::Value::Type::ARRAY] = cbor::Value(array_example);
  type_examples_[cbor::Value::Type::MAP] = cbor::Value(map_example);
  // The TAG type is not supported, skipping it.
  type_examples_[cbor::Value::Type::SIMPLE_VALUE] =
      cbor::Value(cbor::Value::SimpleValue::TRUE_VALUE);

  map_key_examples_[cbor::Value::Type::UNSIGNED] = cbor::Value(42);
  map_key_examples_[cbor::Value::Type::NEGATIVE] = cbor::Value(-42);
  map_key_examples_[cbor::Value::Type::BYTE_STRING] =
      cbor::Value(cbor::Value::BinaryValue({0x42}));
  map_key_examples_[cbor::Value::Type::STRING] = cbor::Value("42");
}

void TestSeries::PromptReplugAndInit() {
  std::cout << "Please replug the device, then hit enter." << std::endl;
  std::cin.ignore();
  CHECK(fido2_tests::Status::kErrNone == device_->Init())
      << "CTAPHID initialization failed";

  platform_cose_key_ = cbor::Value::MapValue();
  shared_secret_ = cbor::Value::BinaryValue();
  auth_token_ = cbor::Value::BinaryValue();
}

bool TestSeries::IsFido2Point1Complicant() {
  return device_tracker_->HasVersion("FIDO_2_1_PRE");
}

cbor::Value TestSeries::MakeTestCredential(const std::string& rp_id,
                                           bool use_residential_key) {
  MakeCredentialCborBuilder test_builder;
  test_builder.AddDefaultsForRequiredFields(rp_id);
  test_builder.SetResidentialKeyOptions(use_residential_key);
  if (!auth_token_.empty()) {
    test_builder.SetDefaultPinUvAuthParam(auth_token_);
    test_builder.SetDefaultPinUvAuthProtocol();
  }

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                 test_builder.GetCbor());
  test_helpers::AssertResponse(response, "make credential for further tests");
  return std::move(absl::get<cbor::Value>(response));
}

void TestSeries::TestBadParameterTypes(Command command, CborBuilder* builder) {
  for (const auto& item : type_examples_) {
    if (item.first != cbor::Value::Type::MAP) {
      Status returned_status = fido2_commands::GenericNegativeTest(
          device_, item.second, command, false);
      device_tracker_->CheckAndReport(
          Status::kErrCborUnexpectedType, returned_status,
          absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                       CommandToString(command), " for the request"));
    }
  }

  const cbor::Value map_cbor = builder->GetCbor();
  for (const auto& map_entry : map_cbor.GetMap()) {
    auto map_key = map_entry.first.Clone();
    CHECK(map_key.is_unsigned()) << "map key not integer - TEST SUITE BUG";
    auto map_value = map_entry.second.Clone();

    // Replace the map value with another of wrong type. Maps and arrays get
    // additional tests.
    for (const auto& item : type_examples_) {
      if (item.second.is_integer() && map_value.is_integer()) {
        continue;
      }
      if (!map_value.is_type(item.first)) {
        builder->SetArbitraryMapEntry(map_key.GetInteger(),
                                      item.second.Clone());
        Status returned_status = fido2_commands::GenericNegativeTest(
            device_, builder->GetCbor(), command, false);
        device_tracker_->CheckAndReport(
            Status::kErrCborUnexpectedType, returned_status,
            absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                         CommandToString(command), " for key ",
                         map_key.GetInteger()));
      }
    }

    if (map_value.is_map()) {
      TestBadParametersInInnerMap(command, builder, map_key.GetInteger(),
                                  map_value.GetMap(), false);
    }

    // Checking types for the first element (assuming all have the same type).
    if (map_value.is_array()) {
      const cbor::Value& element = map_value.GetArray()[0];
      TestBadParametersInInnerArray(command, builder, map_key.GetInteger(),
                                    element);

      if (element.is_map()) {
        TestBadParametersInInnerMap(command, builder, map_key.GetInteger(),
                                    element.GetMap(), true);
      }
    }

    // Undo calls to builder->SetArbitraryMapEntry (including sub-functions).
    builder->SetArbitraryMapEntry(std::move(map_key), std::move(map_value));
  }
}

void TestSeries::TestMissingParameters(Command command, CborBuilder* builder) {
  const cbor::Value map_cbor = builder->GetCbor();
  for (const auto& parameter : map_cbor.GetMap()) {
    auto map_key = parameter.first.Clone();
    auto map_value = parameter.second.Clone();
    builder->RemoveArbitraryMapEntry(map_key.Clone());
    Status returned_status = fido2_commands::GenericNegativeTest(
        device_, builder->GetCbor(), command, false);
    device_tracker_->CheckAndReport(
        Status::kErrMissingParameter, returned_status,
        absl::StrCat("missing ", CborToString("key", map_key), " for command ",
                     CommandToString(command)));
    builder->SetArbitraryMapEntry(std::move(map_key), std::move(map_value));
  }
}

void TestSeries::TestBadParametersInInnerMap(
    Command command, CborBuilder* builder, int outer_map_key,
    const cbor::Value::MapValue& inner_map, bool has_wrapping_array) {
  cbor::Value::MapValue test_map;
  for (const auto& inner_entry : inner_map) {
    test_map[inner_entry.first.Clone()] = inner_entry.second.Clone();
  }
  for (const auto& inner_entry : inner_map) {
    auto inner_key = inner_entry.first.Clone();
    auto inner_value = inner_entry.second.Clone();

    for (const auto& item : type_examples_) {
      if (item.second.is_integer() && inner_value.is_integer()) {
        continue;
      }
      if (!inner_value.is_type(item.first)) {
        test_map[inner_key.Clone()] = item.second.Clone();
        if (has_wrapping_array) {
          cbor::Value::ArrayValue test_array;
          test_array.push_back(cbor::Value(test_map));
          builder->SetArbitraryMapEntry(outer_map_key, cbor::Value(test_array));
        } else {
          builder->SetArbitraryMapEntry(outer_map_key, cbor::Value(test_map));
        }
        Status returned_status = fido2_commands::GenericNegativeTest(
            device_, builder->GetCbor(), command, false);
        device_tracker_->CheckAndReport(
            Status::kErrCborUnexpectedType, returned_status,
            absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                         CommandToString(command), " in ",
                         CborToString("inner key", inner_key),
                         " in array at map key ", outer_map_key));
      }
    }
    test_map[std::move(inner_key)] = std::move(inner_value);
  }
}

void TestSeries::TestBadParametersInInnerArray(
    Command command, CborBuilder* builder, int outer_map_key,
    const cbor::Value& array_element) {
  for (const auto& item : type_examples_) {
    if (item.second.is_integer() && array_element.is_integer()) {
      continue;
    }
    if (!array_element.is_type(item.first)) {
      cbor::Value::ArrayValue test_array;
      test_array.push_back(array_element.Clone());
      test_array.push_back(item.second.Clone());
      builder->SetArbitraryMapEntry(outer_map_key, cbor::Value(test_array));
      Status returned_status = fido2_commands::GenericNegativeTest(
          device_, builder->GetCbor(), command, false);
      device_tracker_->CheckAndReport(
          Status::kErrCborUnexpectedType, returned_status,
          absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                       CommandToString(command),
                       " in array element at map key ", outer_map_key));
    }
  }
}

void TestSeries::TestCredentialDescriptorsArrayForCborDepth(
    Command command, CborBuilder* builder, int map_key,
    const std::string& rp_id) {
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  cbor::Value::BinaryValue cred_descriptor_id(32, 0xce);
  for (const auto& item : type_examples_) {
    if (item.first == cbor::Value::Type::ARRAY ||
        item.first == cbor::Value::Type::MAP) {
      cbor::Value::ArrayValue credential_descriptor_list;
      cbor::Value::MapValue test_cred_descriptor;
      test_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
      test_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
      cbor::Value::ArrayValue transports;
      transports.push_back(cbor::Value("usb"));
      transports.push_back(item.second.Clone());
      test_cred_descriptor[cbor::Value("transports")] = cbor::Value(transports);
      credential_descriptor_list.push_back(cbor::Value(test_cred_descriptor));
      builder->SetArbitraryMapEntry(map_key,
                                    cbor::Value(credential_descriptor_list));
      returned_status = fido2_commands::GenericNegativeTest(
          device_, builder->GetCbor(), command, false);
      device_tracker_->CheckAndReport(
          Status::kErrInvalidCbor, returned_status,
          absl::StrCat("maximum CBOR nesting depth exceeded with ",
                       CborTypeToString(item.first),
                       " in credential descriptor transport list item in ",
                       CommandToString(command), " for key ", map_key));
    }
  }
}

int TestSeries::GetPinRetries() {
  AuthenticatorClientPinCborBuilder get_retries_builder;
  get_retries_builder.AddDefaultsForGetPinRetries();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, get_retries_builder.GetCbor());
  if (absl::holds_alternative<Status>(response) &&
      absl::get<Status>(response) == Status::kErrPinBlocked) {
    std::cout << "getPinRetries was blocked instead of returning 0.\n"
              << "This is neither explicitly allowed nor forbidden."
              << std::endl;
    return 0;
  }
  test_helpers::AssertResponse(response, "get the PIN retries counter");
  return test_helpers::ExtractPinRetries(absl::get<cbor::Value>(response));
}

void TestSeries::ComputeSharedSecret() {
  AuthenticatorClientPinCborBuilder key_agreement_builder;
  key_agreement_builder.AddDefaultsForGetKeyAgreement();
  absl::variant<cbor::Value, Status> key_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, key_agreement_builder.GetCbor());
  device_tracker_->CheckAndReport(key_response, "performing key agreement");
  if (absl::holds_alternative<Status>(key_response)) {
    std::cout << "Since key agreement failed, the next tests might be affected."
              << std::endl;
    return;
  }

  const auto& key_agreement_map = absl::get<cbor::Value>(key_response).GetMap();
  auto map_iter = key_agreement_map.find(cbor::Value(1));
  shared_secret_ = crypto_utility::CompleteEcdhHandshake(
      map_iter->second.GetMap(), &platform_cose_key_);
}

void TestSeries::SetPin(const cbor::Value::BinaryValue& new_pin_utf8) {
  if (platform_cose_key_.empty() || shared_secret_.empty()) {
    ComputeSharedSecret();
  }
  if (!pin_utf8_.empty()) {
    return;
  }
  CHECK(new_pin_utf8.size() >= 4 && new_pin_utf8.size() <= 63)
      << "PIN requirements not fulfilled - TEST SUITE BUG";
  CHECK(new_pin_utf8 != bad_pin_)
      << "new PIN must be different from the bad example PIN - TEST SUITE BUG";

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
  test_helpers::AssertResponse(set_pin_response, "set PIN");
  pin_utf8_ = new_pin_utf8;
  std::cout << "The new PIN is ";
  test_helpers::PrintByteVector(new_pin_utf8);
}

Status TestSeries::AttemptSetPin(
    const cbor::Value::BinaryValue& new_padded_pin) {
  if (platform_cose_key_.empty() || shared_secret_.empty()) {
    ComputeSharedSecret();
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

void TestSeries::ChangePin(const cbor::Value::BinaryValue& new_pin_utf8) {
  SetPin();
  CHECK(new_pin_utf8.size() >= 4 && new_pin_utf8.size() <= 63)
      << "PIN requirements not fulfilled - TEST SUITE BUG";
  CHECK(new_pin_utf8 != bad_pin_)
      << "new PIN must be different from the bad example PIN - TEST SUITE BUG";

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
  test_helpers::AssertResponse(change_pin_response, "change PIN");
  pin_utf8_ = new_pin_utf8;
  std::cout << "The changed PIN is ";
  test_helpers::PrintByteVector(new_pin_utf8);
}

Status TestSeries::AttemptChangePin(
    const cbor::Value::BinaryValue& new_padded_pin) {
  SetPin();

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
  // Since failed PIN checks reset the key agreement, keep the state consistent.
  ComputeSharedSecret();
  return returned_status;
}

void TestSeries::GetAuthToken() {
  SetPin();

  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  pin_token_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(platform_cose_key_,
                                                            pin_hash_enc);
  absl::variant<cbor::Value, Status> pin_token_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, pin_token_builder.GetCbor());
  test_helpers::AssertResponse(pin_token_response, "getting PIN auth token");

  const auto& pin_token_map =
      absl::get<cbor::Value>(pin_token_response).GetMap();
  auto map_iter = pin_token_map.find(cbor::Value(2));
  cbor::Value::BinaryValue encrypted_token = map_iter->second.GetBytestring();
  auth_token_ =
      crypto_utility::Aes256CbcDecrypt(shared_secret_, encrypted_token);
}

Status TestSeries::AttemptGetAuthToken(const cbor::Value::BinaryValue& pin_utf8,
                                       bool redo_key_agreement) {
  SetPin();

  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8));
  pin_token_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(platform_cose_key_,
                                                            pin_hash_enc);
  Status returned_status = fido2_commands::AuthenticatorClientPinNegativeTest(
      device_, pin_token_builder.GetCbor(), false);
  if (redo_key_agreement) {
    // Since failed PIN checks reset the key agreement, keep the state
    // consistent.
    ComputeSharedSecret();
  }
  return returned_status;
}

void TestSeries::CheckPinByGetAuthToken() {
  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  pin_token_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(platform_cose_key_,
                                                            pin_hash_enc);
  absl::variant<cbor::Value, Status> pin_token_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, pin_token_builder.GetCbor());
  device_tracker_->CheckAndReport(pin_token_response,
                                  "PIN was usable for getting an auth token");

  // Since failed PIN checks reset the key agreement, keep the state consistent.
  ComputeSharedSecret();
}

void TestSeries::CheckPinAbsenceByMakeCredential() {
  MakeCredentialCborBuilder pin_test_builder;
  pin_test_builder.AddDefaultsForRequiredFields("pin_absence.example.com");

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                 pin_test_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "no PIN is set, no UV required in MakeCredential");
}

}  // namespace fido2_tests
