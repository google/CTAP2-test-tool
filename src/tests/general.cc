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

#include "src/tests/general.h"

#include "absl/strings/escaping.h"
#include "absl/types/variant.h"
#include "src/constants.h"
#include "src/fido2_commands.h"
#include "src/tests/test_helpers.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

WinkTest::WinkTest()
    : BaseTest("wink", "Tests if the Wink response matches the capability bit.",
               {.has_pin = false}, {}) {}

std::optional<std::string> WinkTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  bool can_wink = device->Wink() == Status::kErrNone;
  if (can_wink != device_tracker->HasWinkCapability()) {
    return "The reported WINK capability did not match the observed response.";
  }
  return std::nullopt;
}

GetInfoTest::GetInfoTest()
    : BaseTest("get_info", "Tests the return values of GetInfo.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetInfoTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetInfoPositiveTest(device, device_tracker);
  if (!device_tracker->CheckStatus(response)) {
    return "Failed to parse GetInfo response.";
  }

  const auto& decoded_map = absl::get<cbor::Value>(response).GetMap();
  auto map_iter = decoded_map.find(CborInt(InfoMember::kPinUvAuthProtocols));
  bool has_pin_protocol_1 = false;
  if (map_iter != decoded_map.end()) {
    for (const auto& pin_protocol : map_iter->second.GetArray()) {
      if (pin_protocol.GetUnsigned() == 1) {
        has_pin_protocol_1 = true;
      }
    }
  }
  if (!has_pin_protocol_1) {
    return "PIN protocol version 1 is not supported.";
  }
  return std::nullopt;
}

PersistentCredentialsTest::PersistentCredentialsTest()
    : BaseTest("persistent_credentials",
               "Tests whether credentials persist after replug.",
               {.has_pin = false}, {}) {}

std::optional<std::string> PersistentCredentialsTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), false);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));

  command_state->PromptReplugAndInit();

  GetAssertionCborBuilder persistence_get_assertion_builder;
  persistence_get_assertion_builder.AddDefaultsForRequiredFields(RpId());
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, persistence_get_assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "A resident key did not persist after replug.";
  }

  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);
  persistence_get_assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, persistence_get_assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "A non-resident key did not persist after replug.";
  }
  return std::nullopt;
}

PersistentPinRetriesTest::PersistentPinRetriesTest()
    : BaseTest("persistent_pin_retries",
               "Tests whether PIN retries persist after replug.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> PersistentPinRetriesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          Status::kErrPinInvalid,
          command_state->AttemptGetAuthToken(
              test_helpers::BadPin(device_tracker->GetMinPinLength())))) {
    return "GetAuthToken did not fail with the wrong PIN.";
  }
  auto reduced_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(reduced_counter)) {
    return absl::get<std::string>(reduced_counter);
  }

  command_state->PromptReplugAndInit();

  auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(reduced_counter) != absl::get<int>(new_counter)) {
    return "PIN retries changed after replug.";
  }
  return std::nullopt;
}

RegeneratesPinAuthTest::RegeneratesPinAuthTest()
    : BaseTest("regenerates_pin_auth",
               "Tests whether the PIN auth token regenerates after replug.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> RegeneratesPinAuthTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  cbor::Value::BinaryValue old_auth_token =
      command_state->GetCurrentAuthToken();

  command_state->PromptReplugAndInit();

  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed unexpectedly.";
  }
  if (command_state->GetCurrentAuthToken() == old_auth_token) {
    return "Auth token was not regenerated after replug.";
  }
  return std::nullopt;
}

}  // namespace fido2_tests

