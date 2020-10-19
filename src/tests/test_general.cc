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
#include "src/tests/test_series.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {

void TestSeries::GetInfoTest(DeviceInterface* device,
                             DeviceTracker* device_tracker,
                             CommandState* command_state) {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device, device_tracker);
  device_tracker->AssertResponse(response, "correct GetInfo response");

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(cbor::Value(3));
  if (map_iter != decoded_map.end()) {
    device_tracker->AssertCondition(map_iter->second.is_bytestring(),
                                    "AAGUID is a bytestring");
    std::cout << "The claimed AAGUID is:" << std::endl;
    test_helpers::PrintByteVector(map_iter->second.GetBytestring());
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
  device_tracker->CheckAndReport(
      has_rk_option, "this test suite expects support of residential keys");
  device_tracker->CheckAndReport(
      has_client_pin_option, "his test suite expects support of client PIN");
  device_tracker->CheckAndReport(
      has_up_option, "his test suite expects support of user presence checks");

  map_iter = decoded_map.find(cbor::Value(6));
  bool has_pin_protocol_1 = false;
  if (map_iter != decoded_map.end()) {
    for (const auto& pin_protocol : map_iter->second.GetArray()) {
      device_tracker->AssertCondition(pin_protocol.is_unsigned(),
                                      "PIN protocol version is unsigned");
      if (pin_protocol.GetUnsigned() == 1) {
        has_pin_protocol_1 = true;
      }
    }
  }
  device_tracker->CheckAndReport(
      has_pin_protocol_1,
      "support of PIN protocol version 1 is expected in this test suite");
}

void TestSeries::PersistenceTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state) {
  std::string rp_id = "persistence.example.com";
  absl::variant<cbor::Value, Status> response;

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);
  cbor::Value credential_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, false);

  command_state->PromptReplugAndInit();

  GetAssertionCborBuilder persistence_get_assertion_builder;
  persistence_get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, persistence_get_assertion_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "residential key persists after replug");

  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);
  persistence_get_assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, persistence_get_assertion_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "non-residential key persists after replug");

  device_tracker->AssertStatus(command_state->SetPin(),
                               "set pin for further tests");
  command_state->AttemptGetAuthToken(test_helpers::BadPin());
  int reduced_counter = test_helpers::GetPinRetries(device, device_tracker);

  command_state->PromptReplugAndInit();

  device_tracker->CheckAndReport(
      test_helpers::GetPinRetries(device, device_tracker) == reduced_counter,
      "PIN retries persist after replug");

  command_state->Reset();
}

}  // namespace fido2_tests
