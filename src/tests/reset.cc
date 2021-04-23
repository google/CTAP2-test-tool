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

#include "src/tests/reset.h"

#include <iostream>

#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/variant.h"
#include "glog/logging.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/fido2_commands.h"
#include "src/tests/test_helpers.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

DeleteCredentialsTest::DeleteCredentialsTest()
    : BaseTest("delete_credential",
               "Tests if Reset actually deletes credentials.",
               {.has_pin = false}, {}) {}

std::optional<std::string> DeleteCredentialsTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  response = command_state->MakeTestCredential(RpId(), false);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));

  GetAssertionCborBuilder reset_get_assertion_builder;
  reset_get_assertion_builder.AddDefaultsForRequiredFields(RpId());
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, reset_get_assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The created credential was already unusable before reset.";
  }

  command_state->Reset();

  // TODO(#16) resolve backwards incompatible user presence precedence
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, reset_get_assertion_builder.GetCbor(),
      !test_helpers::IsFido2Point1Complicant(device_tracker));
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "A resident key was still usable after reset.";
  }

  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);
  reset_get_assertion_builder.SetAllowListCredential(credential_id);
  // TODO(#16) resolve backwards incompatible user presence precedence
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, reset_get_assertion_builder.GetCbor(),
      !test_helpers::IsFido2Point1Complicant(device_tracker));
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "A non-resident key was still usable after reset.";
  }
  return std::nullopt;
}

DeletePinTest::DeletePinTest()
    : BaseTest("delete_pin", "Tests if Reset actually deletes the PIN.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> DeletePinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  auto initial_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(initial_counter)) {
    return absl::get<std::string>(initial_counter);
  }
  if (!device_tracker->CheckStatus(
          Status::kErrPinInvalid,
          command_state->AttemptGetAuthToken(
              test_helpers::BadPin(device_tracker->GetMinPinLength())))) {
    return "GetAuthToken did not fail with the wrong PIN.";
  }
  cbor::Value::BinaryValue old_auth_token =
      command_state->GetCurrentAuthToken();

  command_state->Reset();

  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), false))) {
    return "MakeCredential failed without UV after resetting the PIN.";
  }
  if (!device_tracker->CheckStatus(command_state->SetPin())) {
    return "Failed to set PIN for further tests.";
  }
  auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(initial_counter) != absl::get<int>(new_counter)) {
    return "PIN retries were not reset.";
  }

  MakeCredentialCborBuilder reset_make_credential_builder;
  reset_make_credential_builder.AddDefaultsForRequiredFields(RpId());
  reset_make_credential_builder.SetDefaultPinUvAuthParam(old_auth_token);
  reset_make_credential_builder.SetDefaultPinUvAuthProtocol();
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, reset_make_credential_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinAuthInvalid,
                                   returned_status)) {
    return "The auth token still worked after a reset.";
  }
  return std::nullopt;
}

ResetPhysicalPresenceTest::ResetPhysicalPresenceTest()
    : BaseTest("reset_physical_presence",
               "Tests if Reset requirements are enforced.", {.has_pin = false},
               {Tag::kFido2Point1}) {}

std::optional<std::string> ResetPhysicalPresenceTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  Status returned_status;
  constexpr absl::Duration reset_timeout_duration = absl::Milliseconds(10000);
  absl::Time reset_deadline = absl::Now() + reset_timeout_duration;

  device_tracker->IgnoreNextTouchPrompt();
  test_helpers::PrintNoTouchPrompt();
  returned_status =
      fido2_commands::ResetNegativeTest(device, cbor::Value(), true);
  if (!device_tracker->CheckStatus(Status::kErrUserActionTimeout,
                                   returned_status)) {
    return "Reset was allowed without touch.";
  }

  if (reset_deadline > absl::Now()) {
    std::cout << "Please wait a few seconds for an internal timeout."
              << std::endl;
    absl::SleepFor(reset_deadline - absl::Now());
    std::cout << "Internal timeout elapsed." << std::endl;
  }

  std::cout << "The next touch prompt is valid again." << std::endl;
  returned_status =
      fido2_commands::ResetNegativeTest(device, cbor::Value(), false);
  if (!device_tracker->CheckStatus(Status::kErrNotAllowed, returned_status)) {
    return "Reset was allowed 10 seconds after plugging in.";
  }
  return std::nullopt;
}

}  // namespace fido2_tests

