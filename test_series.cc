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

#include "test_series.h"

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "cbor_builders.h"
#include "constants.h"
#include "crypto_utility.h"
#include "fido2_commands.h"
#include "glog/logging.h"
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
}  // namespace

TestSeries::TestSeries(std::string test_series_name)
    : test_series_name_(std::move(test_series_name)) {}

void TestSeries::PrintResults() {
  std::cout << test_series_name_ << ": passed " << successful_tests_ << " of "
            << total_tests_ << " tests" << std::endl;
}

InputParameterTestSeries::InputParameterTestSeries(
    DeviceInterface* device, DeviceTracker* device_tracker)
    : TestSeries("Input parameter test series"),
      device_(device),
      device_tracker_(device_tracker),
      cose_key_example_(crypto_utility::GenerateExampleEcdhCoseKey()) {
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

void InputParameterTestSeries::MakeCredentialBadParameterTypesTest() {
  std::string rp_id = "make_bad_types.example.com";
  MakeCredentialCborBuilder full_builder;

  full_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("name")] = cbor::Value("example");
  pub_key_cred_rp_entity[cbor::Value("icon")] = cbor::Value("http://icon.png");
  full_builder.SetMapEntry(2, cbor::Value(pub_key_cred_rp_entity));

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("John Doe");
  pub_key_cred_user_entity[cbor::Value("icon")] =
      cbor::Value("http://icon.png");
  pub_key_cred_user_entity[cbor::Value("displayName")] = cbor::Value("JD");
  full_builder.SetMapEntry(3, cbor::Value(pub_key_cred_user_entity));

  full_builder.SetExcludeListCredential(cbor::Value::BinaryValue());
  full_builder.SetMapEntry(6, cbor::Value(cbor::Value::MapValue()));

  cbor::Value::MapValue options;
  options[cbor::Value("rk")] = cbor::Value(false);
  // The correct behavior with "up" isn't specified well, but it should be okay.
  options[cbor::Value("up")] = cbor::Value(true);
  options[cbor::Value("uv")] = cbor::Value(false);
  full_builder.SetMapEntry(7, cbor::Value(options));

  full_builder.SetDefaultPinUvAuthParam(cbor::Value::BinaryValue());
  full_builder.SetDefaultPinUvAuthProtocol();
  TestBadParameterTypes(Command::kAuthenticatorMakeCredential, &full_builder);
}

void InputParameterTestSeries::MakeCredentialMissingParameterTest() {
  std::string rp_id = "make_missing.example.com";
  MakeCredentialCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(rp_id);
  TestMissingParameters(Command::kAuthenticatorMakeCredential,
                        &missing_required_builder);

  // TODO(kaczmarczyck) maybe allow more different errors?
  // For a missing key 4, the Yubikey sends a kErrUnsupportedAlgorithm instead
  // of kErrMissingParameter, which would be correct for an empty list, but here
  // the list is missing entirely.
}

void InputParameterTestSeries::MakeCredentialRelyingPartyEntityTest() {
  constexpr int kKey = 2;
  std::string rp_id = absl::StrCat("make_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder rp_entity_builder;
  rp_entity_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("name")] = cbor::Value("example");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, rp_entity_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "recognize optional name in relying party entity");

  pub_key_cred_rp_entity.clear();
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("icon")] = cbor::Value("http://icon.png");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, rp_entity_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "recognize optional icon in relying party entity");
}

void InputParameterTestSeries::MakeCredentialUserEntityTest() {
  constexpr int kKey = 3;
  std::string rp_id = absl::StrCat("make_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder user_entity_builder;
  user_entity_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, user_entity_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize optional name in user entity");

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("icon")] =
      cbor::Value("http://icon.png");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, user_entity_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize optional icon in user entity");

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("displayName")] = cbor::Value("A L");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, user_entity_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "recognize optional displayName in user entity");
}

void InputParameterTestSeries::MakeCredentialExcludeListTest() {
  constexpr int kKey = 5;
  std::string rp_id = absl::StrCat("make_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(rp_id);
  TestCredentialDescriptorsArrayForCborDepth(
      Command::kAuthenticatorMakeCredential, &exclude_list_builder, kKey,
      rp_id);

  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cbor::Value::BinaryValue cred_descriptor_id(32, 0xce);
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  cbor::Value::ArrayValue credential_descriptor_list;
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  exclude_list_builder.SetMapEntry(kKey,
                                   cbor::Value(credential_descriptor_list));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, exclude_list_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "accept a valid credential descriptor");
}

void InputParameterTestSeries::MakeCredentialExtensionsTest() {
  constexpr int kKey = 6;
  std::string rp_id = absl::StrCat("make_parameter", kKey, ".example.com");

  MakeCredentialCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(rp_id);
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(kKey, cbor::Value(extensions_map));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                 extensions_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "accept valid extension");
}

void InputParameterTestSeries::GetAssertionBadParameterTypesTest() {
  std::string rp_id = "get_bad_types.example.com";
  cbor::Value credential_response = MakeTestCredential(rp_id, false);
  cbor::Value::BinaryValue credential_id =
      ExtractCredentialId(credential_response);

  GetAssertionCborBuilder full_builder;
  full_builder.AddDefaultsForRequiredFields(rp_id);
  full_builder.SetAllowListCredential(credential_id);
  full_builder.SetMapEntry(4, cbor::Value(cbor::Value::MapValue()));

  cbor::Value::MapValue options;
  // "rk" is an invalid option here.
  options[cbor::Value("up")] = cbor::Value(false);
  options[cbor::Value("uv")] = cbor::Value(false);
  full_builder.SetMapEntry(5, cbor::Value(options));

  full_builder.SetDefaultPinUvAuthParam(cbor::Value::BinaryValue());
  full_builder.SetDefaultPinUvAuthProtocol();
  TestBadParameterTypes(Command::kAuthenticatorGetAssertion, &full_builder);
}

void InputParameterTestSeries::GetAssertionMissingParameterTest() {
  std::string rp_id = "get_missing.example.com";
  MakeTestCredential(rp_id, true);

  GetAssertionCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(rp_id);
  TestMissingParameters(Command::kAuthenticatorGetAssertion,
                        &missing_required_builder);
}

void InputParameterTestSeries::GetAssertionAllowListTest() {
  constexpr int kKey = 3;
  std::string rp_id = absl::StrCat("get_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;
  MakeTestCredential(rp_id, true);

  GetAssertionCborBuilder allow_list_builder;
  allow_list_builder.AddDefaultsForRequiredFields(rp_id);
  TestCredentialDescriptorsArrayForCborDepth(
      Command::kAuthenticatorGetAssertion, &allow_list_builder, kKey, rp_id);

  MakeCredentialCborBuilder positive_test_builder;
  positive_test_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, positive_test_builder.GetCbor());
  AssertResponse(response, "create a test key");

  cbor::Value::ArrayValue credential_descriptor_list;
  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cbor::Value::BinaryValue cred_descriptor_id =
      ExtractCredentialId(absl::get<cbor::Value>(response));
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  allow_list_builder.SetMapEntry(kKey, cbor::Value(credential_descriptor_list));
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, allow_list_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "accept a valid credential descriptor");
}

void InputParameterTestSeries::GetAssertionExtensionsTest() {
  constexpr int kKey = 4;
  std::string rp_id = absl::StrCat("get_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;
  cbor::Value credential_response = MakeTestCredential(rp_id, false);
  cbor::Value::BinaryValue credential_id =
      ExtractCredentialId(credential_response);

  GetAssertionCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(rp_id);
  extensions_builder.SetAllowListCredential(credential_id);
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(kKey, cbor::Value(extensions_map));
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, extensions_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "accept a valid extension");
}

void InputParameterTestSeries::ClientPinGetPinRetriesTest() {
  AuthenticatorClientPinCborBuilder pin1_builder;
  pin1_builder.AddDefaultsForGetPinRetries();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin1_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin1_builder);
}

void InputParameterTestSeries::ClientPinGetKeyAgreementTest() {
  // crypto_utility enforces that the COSE key map only has the correct entries.
  AuthenticatorClientPinCborBuilder pin2_builder;
  pin2_builder.AddDefaultsForGetKeyAgreement();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin2_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin2_builder);
}

void InputParameterTestSeries::ClientPinSetPinTest() {
  AuthenticatorClientPinCborBuilder pin3_builder;
  pin3_builder.AddDefaultsForSetPin(cose_key_example_,
                                    cbor::Value::BinaryValue(),
                                    cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin3_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin3_builder);
}

void InputParameterTestSeries::ClientPinChangePinTest() {
  AuthenticatorClientPinCborBuilder pin4_builder;
  pin4_builder.AddDefaultsForChangePin(
      cose_key_example_, cbor::Value::BinaryValue(), cbor::Value::BinaryValue(),
      cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin4_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin4_builder);
}

void InputParameterTestSeries::ClientPinGetPinUvAuthTokenUsingPinTest() {
  AuthenticatorClientPinCborBuilder pin5_builder;
  pin5_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(
      cose_key_example_, cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin5_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin5_builder);
}

void InputParameterTestSeries::ClientPinGetPinUvAuthTokenUsingUvTest() {
  AuthenticatorClientPinCborBuilder pin6_builder;
  pin6_builder.AddDefaultsForGetPinUvAuthTokenUsingUv(cose_key_example_);
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin6_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin6_builder);
}

void InputParameterTestSeries::ClientPinGetUVRetriesTest() {
  AuthenticatorClientPinCborBuilder pin7_builder;
  pin7_builder.AddDefaultsForGetUvRetries();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin7_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin7_builder);
}

cbor::Value InputParameterTestSeries::MakeTestCredential(
    const std::string& rp_id, bool use_residential_key) {
  MakeCredentialCborBuilder test_builder;
  test_builder.AddDefaultsForRequiredFields(rp_id);
  test_builder.SetResidentialKeyOptions(use_residential_key);

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                 test_builder.GetCbor());
  AssertResponse(response, "make credential for further tests");
  return std::move(absl::get<cbor::Value>(response));
}

void InputParameterTestSeries::TestBadParameterTypes(Command command,
                                                     CborBuilder* builder) {
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
        builder->SetMapEntry(map_key.GetInteger(), item.second.Clone());
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

    // All calls to builder->SetMapEntry (including sub-functions) are undone.
    builder->SetMapEntry(std::move(map_key), std::move(map_value));
  }
}

void InputParameterTestSeries::TestMissingParameters(Command command,
                                                     CborBuilder* builder) {
  const cbor::Value map_cbor = builder->GetCbor();
  for (const auto& parameter : map_cbor.GetMap()) {
    auto map_key = parameter.first.Clone();
    CHECK(map_key.is_unsigned()) << "map key not integer - TEST SUITE BUG";
    auto map_value = parameter.second.Clone();
    builder->RemoveMapEntry(map_key.Clone());
    Status returned_status = fido2_commands::GenericNegativeTest(
        device_, builder->GetCbor(), command, false);
    device_tracker_->CheckAndReport(
        Status::kErrMissingParameter, returned_status,
        absl::StrCat("missing key ", map_key.GetInteger(), " for command ",
                     CommandToString(command)));
    builder->SetMapEntry(std::move(map_key), std::move(map_value));
  }
}

void InputParameterTestSeries::TestBadParametersInInnerMap(
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
          builder->SetMapEntry(outer_map_key, cbor::Value(test_array));
        } else {
          builder->SetMapEntry(outer_map_key, cbor::Value(test_map));
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

void InputParameterTestSeries::TestBadParametersInInnerArray(
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
      builder->SetMapEntry(outer_map_key, cbor::Value(test_array));
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

void InputParameterTestSeries::TestCredentialDescriptorsArrayForCborDepth(
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
      builder->SetMapEntry(map_key, cbor::Value(credential_descriptor_list));
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

SpecificationProcedure::SpecificationProcedure(DeviceInterface* device,
                                               DeviceTracker* device_tracker)
    : TestSeries("Specification procedure test series"),
      device_(device),
      device_tracker_(device_tracker),
      bad_pin_({0x66, 0x61, 0x6B, 0x65}) {}

void SpecificationProcedure::MakeCredentialExcludeListTest() {
  std::string rp_id = "exclude.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  cbor::Value credential_response = MakeTestCredential(rp_id, true);

  cbor::Value::BinaryValue cred_descriptor_id =
      ExtractCredentialId(credential_response);
  GetAssertionCborBuilder exclude_assertion_builder;
  exclude_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, exclude_assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "get assertion on recently created credential");

  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(rp_id);
  exclude_list_builder.SetResidentialKeyOptions(true);
  exclude_list_builder.SetPublicKeyCredentialUserEntity(
      cbor::Value::BinaryValue(32, 0x02), "Bob");
  exclude_list_builder.SetExcludeListCredential(cred_descriptor_id);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, exclude_list_builder.GetCbor(), true);
  device_tracker_->CheckAndReport(
      Status::kErrCredentialExcluded, returned_status,
      "credential descriptor is in the exclude list");

  exclude_list_builder.SetDefaultPublicKeyCredentialRpEntity(
      "another.exclude.example.com");
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, exclude_list_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "make a credential for an unrelated relying party");
}

void SpecificationProcedure::MakeCredentialCoseAlgorithmTest() {
  std::string rp_id = "algorithm.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder cose_algorithm_builder;
  cose_algorithm_builder.AddDefaultsForRequiredFields(rp_id);
  cbor::Value::ArrayValue pub_key_cred_params;
  cose_algorithm_builder.SetMapEntry(4, cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, cose_algorithm_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrUnsupportedAlgorithm,
                                  returned_status,
                                  "credential parameters list is empty");

  cbor::Value::MapValue test_cred_param;
  test_cred_param[cbor::Value("alg")] = cbor::Value(-1);  // unassigned number
  test_cred_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(4, cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, cose_algorithm_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrUnsupportedAlgorithm, returned_status,
      "unsupported algorithm in credential parameters");

  pub_key_cred_params.clear();
  test_cred_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kEs256Algorithm));
  test_cred_param[cbor::Value("type")] = cbor::Value("non-existing type");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(4, cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, cose_algorithm_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrUnsupportedAlgorithm,
                                  returned_status,
                                  "unsupported type in credential parameters");

  pub_key_cred_params.clear();
  test_cred_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kEs256Algorithm));
  test_cred_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  test_cred_param[cbor::Value("alg")] = cbor::Value(-1);
  test_cred_param[cbor::Value("type")] = cbor::Value("non-existing type");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(4, cbor::Value(pub_key_cred_params));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, cose_algorithm_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "accept credential parameter list with 1 good and 1 bad item");
}

void SpecificationProcedure::MakeCredentialOptionsTest() {
  std::string rp_id = "options.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(rp_id);
  // The spec is a bit vague about "up" here, but it should be okay if true.

  options_builder.SetResidentialKeyOptions(false);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize resident key option (false)");

  options_builder.SetResidentialKeyOptions(true);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize resident key option (true)");

  options_builder.SetUserPresenceOptions(false);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, options_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrInvalidOption, returned_status,
                                  "reject user presence option set to false");

  options_builder.SetUserPresenceOptions(true);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize user presence option (true)");

  options_builder.SetUserVerificationOptions(false);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize user verification option (false)");

  options_builder.SetUserVerificationOptions(true);
  if (GetInfoHasUvOption()) {
    response = fido2_commands::MakeCredentialPositiveTest(
        device_, device_tracker_, options_builder.GetCbor());
    device_tracker_->CheckAndReport(
        response, "recognize user verification option (true)");
  } else {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device_, options_builder.GetCbor(), false);
    device_tracker_->CheckAndReport(
        Status::kErrInvalidOption, returned_status,
        "recognize user verification option (true) without PIN set");
  }

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(7, cbor::Value(options_map));
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "ignore unknown options");
}

void SpecificationProcedure::MakeCredentialPinAuthTest(
    bool is_fido_2_1_compliant) {
  std::string rp_id = "pinauth.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  if (is_fido_2_1_compliant) {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device_, pin_auth_builder.GetCbor(), true);
    device_tracker_->CheckAndReport(
        Status::kErrPinNotSet, returned_status,
        "PIN auth param has zero length, no PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(9, cbor::Value(123456));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                  "pin protocol is not supported");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinNotSet, returned_status,
                                  "pin not set yet");

  GetAuthToken();
  // Sets a PIN if necessary. From here on, the PIN is set on the authenticator.

  pin_auth_builder.SetDefaultPinUvAuthParam(auth_token_);
  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, pin_auth_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "make credential using PIN token");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  if (is_fido_2_1_compliant) {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device_, pin_auth_builder.GetCbor(), true);
    device_tracker_->CheckAndReport(
        Status::kErrPinInvalid, returned_status,
        "PIN auth param has zero length, but PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                  "pin auth does not match client data hash");

  MakeCredentialCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, no_pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinRequired, returned_status,
                                  "PIN parameter not given, but PIN is set");

  // The specification has only a general statement about error codes, so these
  // are just guesses.
  no_pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, no_pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrPinRequired, returned_status,
      "PIN auth param not given, but PIN protocol is");

  no_pin_auth_builder.RemoveMapEntry(9);
  no_pin_auth_builder.SetDefaultPinUvAuthParam(auth_token_);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, no_pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrMissingParameter, returned_status,
      "PIN protocol not given, but PIN auth param is");

  Reset();
}

void SpecificationProcedure::MakeCredentialMultipleKeysTest(
    int num_credentials) {
  std::string rp_id = "multiple_keys.example.com";
  Status returned_status;

  cbor::Value first_response = MakeTestCredential(rp_id, true);
  cbor::Value second_response = MakeTestCredential(rp_id, true);

  cbor::Value::BinaryValue first_credential_id =
      ExtractCredentialId(first_response);
  cbor::Value::BinaryValue second_credential_id =
      ExtractCredentialId(second_response);
  device_tracker_->CheckAndReport(first_credential_id != second_credential_id,
                                  "the same credential was created twice");

  MakeCredentialCborBuilder residential_key_builder;
  residential_key_builder.AddDefaultsForRequiredFields(rp_id);
  residential_key_builder.SetResidentialKeyOptions(true);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, residential_key_builder.GetCbor(), true);
  uint8_t counter = 0;
  while (returned_status == Status::kErrNone && counter != num_credentials) {
    counter += 1;
    residential_key_builder.SetPublicKeyCredentialUserEntity(
        cbor::Value::BinaryValue(32, counter), "Greedy Greg");
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device_, residential_key_builder.GetCbor(), true);
  }
  if (counter != num_credentials) {
    device_tracker_->CheckAndReport(
        Status::kErrKeyStoreFull, returned_status,
        "full keystore after creating lots of residential keys");
  } else {
    std::cout << "Omitting to test filling up the key store, over "
              << num_credentials << " keys fit." << std::endl;
  }

  Reset();
}

void SpecificationProcedure::MakeCredentialPhysicalPresenceTest() {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  PrintNoTouchPrompt();

  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(rp_id);
  make_credential_builder.SetResidentialKeyOptions(true);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, make_credential_builder.GetCbor(), true);
  device_tracker_->CheckAndReport(Status::kErrUserActionTimeout,
                                  returned_status,
                                  "key was not touched for make credential");

  // TODO(kaczmarczcyk) ask user for confirmation of flashing LED?

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, get_assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrNoCredentials, returned_status,
                                  "the asserted credential shouldn't exist");
}

void SpecificationProcedure::MakeCredentialDisplayNameEncodingTest() {
  std::string rp_id = "displayname.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(rp_id);
  make_credential_builder.SetResidentialKeyOptions(true);
  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(std::move(user_id));
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  std::string long_kanji_name =
      "猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫"
      "猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫"
      "猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫猫";
  // We first test a short non-ASCII name, and then try to catch authenticators
  // trying to truncate display names through multi-byte chars. Since 猫 is
  // represented by 3 byte, we perform 3 tests to cover all alignments.
  std::string display_names[] = {"テスト", long_kanji_name,
                                 absl::StrCat("0", long_kanji_name),
                                 absl::StrCat("01", long_kanji_name)};

  for (std::string display_name : display_names) {
    pub_key_cred_user_entity[cbor::Value("displayName")] =
        cbor::Value(std::move(display_name));
    make_credential_builder.SetMapEntry(3,
                                        cbor::Value(pub_key_cred_user_entity));

    response = fido2_commands::MakeCredentialPositiveTest(
        device_, device_tracker_, make_credential_builder.GetCbor());
    device_tracker_->CheckAndReport(
        response, "accept displayName with non-ASCII characters");
  }

  std::string display_name = "テスト";
  pub_key_cred_user_entity[cbor::Value("displayName")] =
      cbor::Value(display_name);
  make_credential_builder.SetMapEntry(
      3, cbor::Value(std::move(pub_key_cred_user_entity)));

  auto encoded_request = cbor::Writer::Write(make_credential_builder.GetCbor());
  CHECK(encoded_request.has_value()) << "encoding went wrong - TEST SUITE BUG";
  cbor::Value::BinaryValue req_cbor = encoded_request.value();

  std::vector<uint8_t> display_name_bytes(display_name.begin(),
                                          display_name.end());
  auto iter = std::search(req_cbor.begin(), req_cbor.end(),
                          display_name_bytes.begin(), display_name_bytes.end());
  CHECK(iter != req_cbor.end()) << "encoding problem - TEST SUITE BUG";
  // Generating an invalid UTF-8 encoding here.
  *iter = 0x80;
  returned_status = fido2_commands::NonCborNegativeTest(
      device_, req_cbor, Command::kAuthenticatorMakeCredential, false);
  if (returned_status != Status::kErrInvalidCbor) {
    device_tracker_->AddProblem("UTF-8 correctness is not checked.");
  }
}

void SpecificationProcedure::MakeCredentialHmacSecretTest() {
  std::string rp_id = "hmac-secret.example.com";
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder hmac_secret_builder;
  hmac_secret_builder.AddDefaultsForRequiredFields(rp_id);
  hmac_secret_builder.SetResidentialKeyOptions(true);

  cbor::Value::MapValue extension_map;
  extension_map[cbor::Value("hmac-secret")] = cbor::Value(true);
  hmac_secret_builder.SetMapEntry(6, cbor::Value(extension_map));

  response = fido2_commands::MakeCredentialPositiveTest(
      device_, device_tracker_, hmac_secret_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "make credential with HMAC-secret extension");
}

void SpecificationProcedure::GetAssertionOptionsTest() {
  std::string rp_id = "options.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeTestCredential(rp_id, true);
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("rk")] = cbor::Value(false);
  options_builder.SetMapEntry(5, cbor::Value(authenticator_options));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, options_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrInvalidOption, returned_status,
      "reject invalid residential key option (false)");

  authenticator_options[cbor::Value("rk")] = cbor::Value(true);
  options_builder.SetMapEntry(5, cbor::Value(authenticator_options));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, options_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrInvalidOption, returned_status,
      "reject invalid residential key option (true)");

  options_builder.SetUserPresenceOptions(false);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize user presence option (false)");

  options_builder.SetUserPresenceOptions(true);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize user presence option (true)");

  options_builder.SetUserVerificationOptions(false);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "recognize user verification option (false)");

  options_builder.SetUserVerificationOptions(true);
  if (GetInfoHasUvOption()) {
    response = fido2_commands::GetAssertionPositiveTest(
        device_, device_tracker_, options_builder.GetCbor());
    device_tracker_->CheckAndReport(
        response, "recognize user verification option (true)");
  } else {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device_, options_builder.GetCbor(), false);
    device_tracker_->CheckAndReport(
        Status::kErrInvalidOption, returned_status,
        "recognize user verification option (true) without PIN set");
  }

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(5, cbor::Value(options_map));
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, options_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "ignore unknown options");
}

void SpecificationProcedure::GetAssertionResidentialKeyTest() {
  std::string rp_id = "residential.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  GetAssertionCborBuilder assertion_builder;
  assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "there should be no credentials for this relying party");

  MakeTestCredential(rp_id, true);

  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "get assertion for residential key");

  rp_id = "non-residential.example.com";
  assertion_builder.SetRelyingParty(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "there should be no credentials for this relying party");

  cbor::Value credential_response = MakeTestCredential(rp_id, false);

  cbor::Value::BinaryValue credential_id =
      ExtractCredentialId(credential_response);
  assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "get assertion for non-residental key");

  cbor::Value::BinaryValue fake_credential_id =
      cbor::Value::BinaryValue(credential_id.size(), 0xFA);
  assertion_builder.SetAllowListCredential(fake_credential_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrNoCredentials, returned_status,
                                  "this credential ID is fake");
}

void SpecificationProcedure::GetAssertionPinAuthTest(
    bool is_fido_2_1_compliant) {
  std::string rp_id = "pinauth.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeTestCredential(rp_id, true);

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  if (is_fido_2_1_compliant) {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device_, pin_auth_builder.GetCbor(), true);
    device_tracker_->CheckAndReport(
        Status::kErrPinNotSet, returned_status,
        "PIN auth param has zero length, no PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(7, cbor::Value(123456));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                  "pin protocol is not supported");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinNotSet, returned_status,
                                  "pin not set yet");

  GetAuthToken();
  // Sets a PIN if necessary. From here on, the PIN is set on the authenticator.

  pin_auth_builder.SetDefaultPinUvAuthParam(auth_token_);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, pin_auth_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "get assertion using PIN token");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  if (is_fido_2_1_compliant) {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device_, pin_auth_builder.GetCbor(), true);
    device_tracker_->CheckAndReport(
        Status::kErrPinInvalid, returned_status,
        "PIN auth param has zero length, but PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                  "pin auth does not match client data hash");

  MakeTestCredential(rp_id, true);

  GetAssertionCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, no_pin_auth_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "get assertion with a PIN set, but without a token");

  no_pin_auth_builder.SetDefaultPinUvAuthParam(auth_token_);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, no_pin_auth_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrMissingParameter, returned_status,
      "PIN protocol not given, but PIN auth param is");

  Reset();
}

void SpecificationProcedure::GetAssertionPhysicalPresenceTest() {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeTestCredential(rp_id, true);
  PrintNoTouchPrompt();

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, get_assertion_builder.GetCbor(), true);
  device_tracker_->CheckAndReport(Status::kErrUserActionTimeout,
                                  returned_status,
                                  "key was not touched for get assertion");

  // TODO(kaczmarczcyk) ask user for confirmation of flashing LED?
}

// TODO(kaczmarczyck) case of multiple available credentials + GetNextAssertion

// TODO(kaczmarczyck) check returned signature crypto

void SpecificationProcedure::GetInfoTest() {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device_);
  AssertResponse(response, "correct GetInfo response");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(cbor::Value(3));
  if (map_iter != decoded_map.end()) {
    AssertCondition(map_iter->second.is_bytestring(), "AAGUID is a bytestring");
    std::cout << "The claimed AAGUID is:" << std::endl;
    PrintByteVector(map_iter->second.GetBytestring());
  }

  map_iter = decoded_map.find(cbor::Value(4));
  bool has_rk_option = false;
  bool has_client_pin_option = false;
  bool has_up_option = true;
  if (map_iter != decoded_map.end()) {
    for (const auto& option : map_iter->second.GetMap()) {
      if (option.first.GetString() == "rk") {
        has_rk_option = option.second.GetBool();
      }
      if (option.first.GetString() == "clientPin") {
        has_client_pin_option = true;
      }
      if (option.first.GetString() == "up") {
        has_up_option = option.second.GetBool();
      }
    }
  }
  device_tracker_->CheckAndReport(
      has_rk_option, "this test suite expects support of residential keys");
  device_tracker_->CheckAndReport(
      has_client_pin_option, "his test suite expects support of client PIN");
  device_tracker_->CheckAndReport(
      has_up_option, "his test suite expects support of user presence checks");

  map_iter = decoded_map.find(cbor::Value(6));
  bool has_pin_protocol_1 = false;
  if (map_iter != decoded_map.end()) {
    for (const auto& pin_protocol : map_iter->second.GetArray()) {
      AssertCondition(pin_protocol.is_unsigned(),
                      "PIN protocol version is unsigned");
      if (pin_protocol.GetUnsigned() == 1) {
        has_pin_protocol_1 = true;
      }
    }
  }
  device_tracker_->CheckAndReport(
      has_pin_protocol_1,
      "support of PIN protocol version 1 is expected in this test suite");
}

bool SpecificationProcedure::GetInfoIs2Point1Compliant() {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device_);
  AssertResponse(response, "correct GetInfo response");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(cbor::Value(1));
  if (map_iter != decoded_map.end()) {
    for (const auto& fido_version : map_iter->second.GetArray()) {
      if (fido_version.GetString() == "FIDO_2_1") {
        return true;
      }
    }
  }
  return false;
}

bool SpecificationProcedure::GetInfoHasUvOption() {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device_);
  AssertResponse(response, "correct GetInfo response");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(cbor::Value(4));
  if (map_iter != decoded_map.end()) {
    for (const auto& option : map_iter->second.GetMap()) {
      if (option.first.GetString() == "uv") {
        return option.second.GetBool();
      }
    }
  }
  return false;
}

bool SpecificationProcedure::GetInfoIsHmacSecretSupported() {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device_);
  AssertResponse(response, "correct GetInfo response");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(cbor::Value(2));
  if (map_iter != decoded_map.end()) {
    for (const auto& extension_name : map_iter->second.GetArray()) {
      if (extension_name.GetString() == "hmac-secret") {
        return true;
      }
    }
  }
  return false;
}

void SpecificationProcedure::ClientPinRequirementsTest() {
  Status returned_status;

  cbor::Value::BinaryValue too_short_pin_utf8 = {0x31, 0x32, 0x33};
  cbor::Value::BinaryValue too_short_padded_pin =
      cbor::Value::BinaryValue(64, 0x00);
  for (size_t i = 0; i < too_short_pin_utf8.size(); ++i) {
    too_short_padded_pin[i] = too_short_pin_utf8[i];
  }
  returned_status = AttemptSetPin(too_short_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN of length < 4");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  cbor::Value::BinaryValue too_long_padded_pin =
      cbor::Value::BinaryValue(64, 0x30);
  returned_status = AttemptSetPin(too_long_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN of length > 63");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  cbor::Value::BinaryValue valid_pin_utf8 = {0x31, 0x32, 0x33, 0x34};
  cbor::Value::BinaryValue too_short_padding = cbor::Value::BinaryValue(32);
  for (size_t i = 0; i < valid_pin_utf8.size(); ++i) {
    too_short_padding[i] = valid_pin_utf8[i];
  }
  returned_status = AttemptSetPin(too_short_padding);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN padding of length 32");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  cbor::Value::BinaryValue too_long_padding = cbor::Value::BinaryValue(128);
  for (size_t i = 0; i < valid_pin_utf8.size(); ++i) {
    too_long_padding[i] = valid_pin_utf8[i];
  }
  returned_status = AttemptSetPin(too_long_padding);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN padding of length 128");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  // The minimum length is 4, but the authenticator can enforce more, so only
  // testing the maximum length here.
  cbor::Value::BinaryValue maximum_pin_utf8 =
      cbor::Value::BinaryValue(63, 0x30);
  SetPin(maximum_pin_utf8);
  CheckPinByGetAuthToken();

  returned_status = AttemptChangePin(too_short_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to change to a PIN of length < 4");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  returned_status = AttemptChangePin(too_long_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to change to a PIN of length > 63");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  returned_status = AttemptChangePin(too_short_padding);
  device_tracker_->CheckAndReport(
      Status::kErrPinPolicyViolation, returned_status,
      "reject to change to a PIN padding of length 32");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  returned_status = AttemptChangePin(too_long_padding);
  device_tracker_->CheckAndReport(
      Status::kErrPinPolicyViolation, returned_status,
      "reject to change to a PIN padding of length 128");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    Reset();
  }

  // Again only testing maximum, not minimum PIN length.
  ChangePin(maximum_pin_utf8);
  CheckPinByGetAuthToken();
}

void SpecificationProcedure::ClientPinRetriesTest() {
  Status returned_status;

  int initial_counter = GetPinRetries();
  device_tracker_->CheckAndReport(
      initial_counter <= 8, "maximum PIN retries holds the upper limit of 8");
  device_tracker_->CheckAndReport(initial_counter > 0,
                                  "maximum PIN retries is positive");
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter,
      "PIN retries changed between subsequent calls");

  returned_status = AttemptGetAuthToken(bad_pin_);
  device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                  "reject wrong PIN");
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter - 1,
      "PIN retries decrement after a failed attempt");

  GetAuthToken();
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter,
      "PIN retries reset on entering the correct PIN");

  constexpr int kWrongPinsBeforePowerCycle = 3;
  if (initial_counter > kWrongPinsBeforePowerCycle) {
    for (int i = 0; i < kWrongPinsBeforePowerCycle - 1; ++i) {
      returned_status = AttemptGetAuthToken(bad_pin_);
      device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                      "reject wrong PIN");
    }
    returned_status = AttemptGetAuthToken(bad_pin_);
    device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked, returned_status,
                                    "reject PIN before power cycle");
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter - kWrongPinsBeforePowerCycle,
        "PIN retry counter decremented until blocked");
    returned_status = AttemptGetAuthToken(bad_pin_);

    device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked, returned_status,
                                    "reject PIN before power cycle");
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter - kWrongPinsBeforePowerCycle,
        "PIN retry counter does not decrement in a blocked operation");
    PromptReplugAndInit();
    GetAuthToken();
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter,
        "PIN retries reset on entering the correct PIN");
  } else {
    std::cout << "The tests for power cycle requirement on "
              << kWrongPinsBeforePowerCycle
              << " consecutive wrong PINs are skipped, because there are at "
                 "most that many retries anyway."
              << std::endl;
  }

  // The next test checks whether the authenticator resets his own key agreement
  // key by reusing the old key material and see if it still works.
  returned_status = AttemptGetAuthToken(bad_pin_, false);
  device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                  "reject wrong PIN");
  returned_status = AttemptGetAuthToken(pin_utf8_);
  device_tracker_->CheckAndReport(
      Status::kErrPinInvalid, returned_status,
      "reject even the correct PIN if shared secrets do not match");
  PromptReplugAndInit();

  int remaining_retries = GetPinRetries();
  for (int i = 0; i < remaining_retries - 1; ++i) {
    returned_status = AttemptGetAuthToken(bad_pin_);
    if (i % 3 != 2) {
      device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                      "reject wrong PIN");
    } else {
      device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked,
                                      returned_status, "reject wrong PIN");
      PromptReplugAndInit();
    }
  }
  device_tracker_->CheckAndReport(GetPinRetries() == 1,
                                  "PIN retry counter was reduced to 1");
  returned_status = AttemptGetAuthToken(bad_pin_);
  device_tracker_->CheckAndReport(Status::kErrPinBlocked, returned_status,
                                  "block PIN retries if the counter gets to 0");
  device_tracker_->CheckAndReport(GetPinRetries() == 0,
                                  "PIN retry counter was reduced to 0");
  returned_status = AttemptGetAuthToken(pin_utf8_);
  device_tracker_->CheckAndReport(
      Status::kErrPinBlocked, returned_status,
      "reject even the correct PIN if the retry counter is 0");

  Reset();
  // TODO(kaczmarczyck) check optional powerCycleState
}

void SpecificationProcedure::Reset() {
  std::cout << "You have 10 seconds for the next touch after pressing enter.\n";
  PromptReplugAndInit();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::ResetPositiveTest(device_);
  AssertResponse(response, "resetting the device");

  platform_cose_key_ = cbor::Value::MapValue();
  shared_secret_ = cbor::Value::BinaryValue();
  pin_utf8_ = cbor::Value::BinaryValue();
  auth_token_ = cbor::Value::BinaryValue();
}

void SpecificationProcedure::ResetDeletionTest() {
  std::string rp_id = "reset.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeTestCredential(rp_id, true);
  cbor::Value credential_response = MakeTestCredential(rp_id, false);

  GetAssertionCborBuilder reset_get_assertion_builder;
  reset_get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, reset_get_assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(response, "get assertion before reset");

  Reset();

  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, reset_get_assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "get assertion of residential key after reset");

  cbor::Value::BinaryValue credential_id =
      ExtractCredentialId(credential_response);
  reset_get_assertion_builder.SetAllowListCredential(credential_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, reset_get_assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "get assertion of non-residential key after reset");

  SetPin();
  int initial_counter = GetPinRetries();
  AttemptGetAuthToken(bad_pin_);
  cbor::Value::BinaryValue old_auth_token = auth_token_;

  Reset();

  CheckPinAbsenceByMakeCredential();
  SetPin();
  device_tracker_->CheckAndReport(GetPinRetries() == initial_counter,
                                  "PIN retries reset on reset command");

  MakeCredentialCborBuilder reset_make_credential_builder;
  reset_make_credential_builder.AddDefaultsForRequiredFields(rp_id);
  reset_make_credential_builder.SetDefaultPinUvAuthParam(old_auth_token);
  reset_make_credential_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device_, reset_make_credential_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                  "PIN auth was reset, token stops working");

  Reset();
}

void SpecificationProcedure::ResetPhysicalPresenceTest() {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  constexpr absl::Duration reset_timeout_duration = absl::Milliseconds(10000);
  absl::Time reset_timeout = absl::Now() + reset_timeout_duration;

  PrintNoTouchPrompt();
  // TODO(kaczmarczcyk) ask user for confirmation of flashing LED?

  returned_status =
      fido2_commands::ResetNegativeTest(device_, cbor::Value(), true);
  device_tracker_->CheckAndReport(Status::kErrUserActionTimeout,
                                  returned_status,
                                  "key was not touched for reset");

  if (reset_timeout > absl::Now()) {
    std::cout << "Please wait a few seconds for an internal timeout."
              << std::endl;
    absl::SleepFor(reset_timeout - absl::Now());
    std::cout << "Internal timeout elapsed." << std::endl;
  }

  std::cout << "The next touch prompt is valid again." << std::endl;
  returned_status =
      fido2_commands::ResetNegativeTest(device_, cbor::Value(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNotAllowed, returned_status,
      "reset not allowed more than 10 seconds after plugging in");
}

void SpecificationProcedure::PersistenceTest() {
  std::string rp_id = "persistence.example.com";
  absl::variant<cbor::Value, Status> response;

  MakeTestCredential(rp_id, true);
  cbor::Value credential_response = MakeTestCredential(rp_id, false);

  PromptReplugAndInit();

  GetAssertionCborBuilder persistence_get_assertion_builder;
  persistence_get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, persistence_get_assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "residential key persists after replug");

  cbor::Value::BinaryValue credential_id =
      ExtractCredentialId(credential_response);
  persistence_get_assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device_, device_tracker_, persistence_get_assertion_builder.GetCbor());
  device_tracker_->CheckAndReport(response,
                                  "non-residential key persists after replug");

  SetPin();
  AttemptGetAuthToken(bad_pin_);
  int reduced_counter = GetPinRetries();

  PromptReplugAndInit();

  device_tracker_->CheckAndReport(GetPinRetries() == reduced_counter,
                                  "PIN retries persist after replug");

  Reset();
}

void SpecificationProcedure::PromptReplugAndInit() {
  std::cout << "Please replug the device, then hit enter." << std::endl;
  std::cin.ignore();
  CHECK(fido2_tests::Status::kErrNone == device_->Init())
      << "CTAPHID initialization failed";

  platform_cose_key_ = cbor::Value::MapValue();
  shared_secret_ = cbor::Value::BinaryValue();
  auth_token_ = cbor::Value::BinaryValue();
}

cbor::Value SpecificationProcedure::MakeTestCredential(
    const std::string& rp_id, bool use_residential_key) {
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
  AssertResponse(response, "make credential for further tests");
  return std::move(absl::get<cbor::Value>(response));
}

int SpecificationProcedure::GetPinRetries() {
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
  AssertResponse(response, "get the PIN retries counter");
  return ExtractPinRetries(absl::get<cbor::Value>(response));
}

void SpecificationProcedure::ComputeSharedSecret() {
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

void SpecificationProcedure::SetPin(
    const cbor::Value::BinaryValue& new_pin_utf8) {
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
  AssertResponse(set_pin_response, "set PIN");
  pin_utf8_ = new_pin_utf8;
  std::cout << "The new PIN is ";
  PrintByteVector(new_pin_utf8);
}

Status SpecificationProcedure::AttemptSetPin(
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

void SpecificationProcedure::ChangePin(
    const cbor::Value::BinaryValue& new_pin_utf8) {
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
  AssertResponse(change_pin_response, "change PIN");
  pin_utf8_ = new_pin_utf8;
  std::cout << "The changed PIN is ";
  PrintByteVector(new_pin_utf8);
}

Status SpecificationProcedure::AttemptChangePin(
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

void SpecificationProcedure::GetAuthToken() {
  SetPin();

  AuthenticatorClientPinCborBuilder pin_token_builder;
  cbor::Value::BinaryValue pin_hash_enc = crypto_utility::Aes256CbcEncrypt(
      shared_secret_, crypto_utility::LeftSha256Hash(pin_utf8_));
  pin_token_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(platform_cose_key_,
                                                            pin_hash_enc);
  absl::variant<cbor::Value, Status> pin_token_response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device_, device_tracker_, pin_token_builder.GetCbor());
  AssertResponse(pin_token_response, "getting PIN auth token");

  const auto& pin_token_map =
      absl::get<cbor::Value>(pin_token_response).GetMap();
  auto map_iter = pin_token_map.find(cbor::Value(2));
  cbor::Value::BinaryValue encrypted_token = map_iter->second.GetBytestring();
  auth_token_ =
      crypto_utility::Aes256CbcDecrypt(shared_secret_, encrypted_token);
}

Status SpecificationProcedure::AttemptGetAuthToken(
    const cbor::Value::BinaryValue& pin_utf8, bool redo_key_agreement) {
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

void SpecificationProcedure::CheckPinByGetAuthToken() {
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

void SpecificationProcedure::CheckPinAbsenceByMakeCredential() {
  MakeCredentialCborBuilder pin_test_builder;
  pin_test_builder.AddDefaultsForRequiredFields("pin_absence.example.com");

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device_, device_tracker_,
                                                 pin_test_builder.GetCbor());
  device_tracker_->CheckAndReport(
      response, "no PIN is set, no UV required in MakeCredential");
}

}  // namespace fido2_tests
