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
// These are arbitrary example values for each CBOR type.
const std::map<cbor::Value::Type, cbor::Value>& GetTypeExamples() {
  static const auto* const kTypeExamples = [] {
    auto* type_examples = new std::map<cbor::Value::Type, cbor::Value>;
    cbor::Value::ArrayValue array_example;
    array_example.push_back(cbor::Value(42));
    cbor::Value::MapValue map_example;
    map_example[cbor::Value(42)] = cbor::Value(42);
    (*type_examples)[cbor::Value::Type::UNSIGNED] = cbor::Value(42);
    (*type_examples)[cbor::Value::Type::NEGATIVE] = cbor::Value(-42);
    (*type_examples)[cbor::Value::Type::BYTE_STRING] =
        cbor::Value(cbor::Value::BinaryValue({0x42}));
    (*type_examples)[cbor::Value::Type::STRING] = cbor::Value("42");
    (*type_examples)[cbor::Value::Type::ARRAY] = cbor::Value(array_example);
    (*type_examples)[cbor::Value::Type::MAP] = cbor::Value(map_example);
    // The TAG type is not supported, skipping it.
    (*type_examples)[cbor::Value::Type::SIMPLE_VALUE] =
        cbor::Value(cbor::Value::SimpleValue::TRUE_VALUE);
    return type_examples;
  }();
  return *kTypeExamples;
}

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

cbor::Value::BinaryValue BadPin() { return {0x66, 0x61, 0x6B, 0x65}; }

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

bool IsFido2Point1Complicant(DeviceTracker* device_tracker) {
  return device_tracker->HasVersion("FIDO_2_1_PRE");
}

cbor::Value MakeTestCredential(DeviceTracker* device_tracker,
                               CommandState* command_state,
                               const std::string& rp_id,
                               bool use_residential_key) {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(rp_id, use_residential_key);
  device_tracker->AssertResponse(response, "make credential for further tests");
  return std::move(absl::get<cbor::Value>(response));
}

void TestBadParameterTypes(DeviceInterface* device,
                           DeviceTracker* device_tracker, Command command,
                           CborBuilder* builder) {
  for (const auto& item : GetTypeExamples()) {
    if (item.first != cbor::Value::Type::MAP) {
      Status returned_status = fido2_commands::GenericNegativeTest(
          device, item.second, command, false);
      device_tracker->CheckAndReport(
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
    for (const auto& item : GetTypeExamples()) {
      if (item.second.is_integer() && map_value.is_integer()) {
        continue;
      }
      if (!map_value.is_type(item.first)) {
        builder->SetArbitraryMapEntry(map_key.GetInteger(),
                                      item.second.Clone());
        Status returned_status = fido2_commands::GenericNegativeTest(
            device, builder->GetCbor(), command, false);
        device_tracker->CheckAndReport(
            Status::kErrCborUnexpectedType, returned_status,
            absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                         CommandToString(command), " for key ",
                         map_key.GetInteger()));
      }
    }

    if (map_value.is_map()) {
      TestBadParametersInInnerMap(device, device_tracker, command, builder,
                                  map_key.GetInteger(), map_value.GetMap(),
                                  false);
    }

    // Checking types for the first element (assuming all have the same type).
    if (map_value.is_array()) {
      const cbor::Value& element = map_value.GetArray()[0];
      TestBadParametersInInnerArray(device, device_tracker, command, builder,
                                    map_key.GetInteger(), element);

      if (element.is_map()) {
        TestBadParametersInInnerMap(device, device_tracker, command, builder,
                                    map_key.GetInteger(), element.GetMap(),
                                    true);
      }
    }

    // Undo calls to builder->SetArbitraryMapEntry (including sub-functions).
    builder->SetArbitraryMapEntry(std::move(map_key), std::move(map_value));
  }
}

void TestMissingParameters(DeviceInterface* device,
                           DeviceTracker* device_tracker, Command command,
                           CborBuilder* builder) {
  const cbor::Value map_cbor = builder->GetCbor();
  for (const auto& parameter : map_cbor.GetMap()) {
    auto map_key = parameter.first.Clone();
    auto map_value = parameter.second.Clone();
    builder->RemoveArbitraryMapEntry(map_key.Clone());
    Status returned_status = fido2_commands::GenericNegativeTest(
        device, builder->GetCbor(), command, false);
    device_tracker->CheckAndReport(
        Status::kErrMissingParameter, returned_status,
        absl::StrCat("missing ", CborToString("key", map_key), " for command ",
                     CommandToString(command)));
    builder->SetArbitraryMapEntry(std::move(map_key), std::move(map_value));
  }
}

void TestBadParametersInInnerMap(DeviceInterface* device,
                                 DeviceTracker* device_tracker, Command command,
                                 CborBuilder* builder, int outer_map_key,
                                 const cbor::Value::MapValue& inner_map,
                                 bool has_wrapping_array) {
  cbor::Value::MapValue test_map;
  for (const auto& inner_entry : inner_map) {
    test_map[inner_entry.first.Clone()] = inner_entry.second.Clone();
  }
  for (const auto& inner_entry : inner_map) {
    auto inner_key = inner_entry.first.Clone();
    auto inner_value = inner_entry.second.Clone();

    for (const auto& item : GetTypeExamples()) {
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
            device, builder->GetCbor(), command, false);
        device_tracker->CheckAndReport(
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

void TestBadParametersInInnerArray(DeviceInterface* device,
                                   DeviceTracker* device_tracker,
                                   Command command, CborBuilder* builder,
                                   int outer_map_key,
                                   const cbor::Value& array_element) {
  for (const auto& item : GetTypeExamples()) {
    if (item.second.is_integer() && array_element.is_integer()) {
      continue;
    }
    if (!array_element.is_type(item.first)) {
      cbor::Value::ArrayValue test_array;
      test_array.push_back(array_element.Clone());
      test_array.push_back(item.second.Clone());
      builder->SetArbitraryMapEntry(outer_map_key, cbor::Value(test_array));
      Status returned_status = fido2_commands::GenericNegativeTest(
          device, builder->GetCbor(), command, false);
      device_tracker->CheckAndReport(
          Status::kErrCborUnexpectedType, returned_status,
          absl::StrCat("bad type ", CborTypeToString(item.first), " in ",
                       CommandToString(command),
                       " in array element at map key ", outer_map_key));
    }
  }
}

void TestCredentialDescriptorsArrayForCborDepth(
    DeviceInterface* device, DeviceTracker* device_tracker, Command command,
    CborBuilder* builder, int map_key, const std::string& rp_id) {
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  cbor::Value::BinaryValue cred_descriptor_id(32, 0xce);
  for (const auto& item : GetTypeExamples()) {
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
          device, builder->GetCbor(), command, false);
      device_tracker->CheckAndReport(
          Status::kErrInvalidCbor, returned_status,
          absl::StrCat("maximum CBOR nesting depth exceeded with ",
                       CborTypeToString(item.first),
                       " in credential descriptor transport list item in ",
                       CommandToString(command), " for key ", map_key));
    }
  }
}

int GetPinRetries(DeviceInterface* device, DeviceTracker* device_tracker) {
  AuthenticatorClientPinCborBuilder get_retries_builder;
  get_retries_builder.AddDefaultsForGetPinRetries();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::AuthenticatorClientPinPositiveTest(
          device, device_tracker, get_retries_builder.GetCbor());
  if (absl::holds_alternative<Status>(response) &&
      absl::get<Status>(response) == Status::kErrPinBlocked) {
    std::cout << "getPinRetries was blocked instead of returning 0.\n"
              << "This is neither explicitly allowed nor forbidden."
              << std::endl;
    return 0;
  }
  device_tracker->AssertResponse(response, "get the PIN retries counter");
  return ExtractPinRetries(absl::get<cbor::Value>(response));
}

void CheckPinByGetAuthToken(DeviceTracker* device_tracker,
                            CommandState* command_state) {
  device_tracker->CheckAndReport(command_state->GetAuthToken(false),
                                 "PIN was usable for getting an auth token");
}

void CheckPinAbsenceByMakeCredential(DeviceInterface* device,
                                     DeviceTracker* device_tracker) {
  MakeCredentialCborBuilder pin_test_builder;
  pin_test_builder.AddDefaultsForRequiredFields("pin_absence.example.com");

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 pin_test_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "no PIN is set, no UV required in MakeCredential");
}

}  // namespace test_helpers
}  // namespace fido2_tests
