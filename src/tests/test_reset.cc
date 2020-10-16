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

void TestSeries::ResetDeletionTest() {
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

  command_state_->Reset();

  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, reset_get_assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "get assertion of residential key after reset");

  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);
  reset_get_assertion_builder.SetAllowListCredential(credential_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device_, reset_get_assertion_builder.GetCbor(), false);
  device_tracker_->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "get assertion of non-residential key after reset");

  device_tracker_->AssertStatus(command_state_->SetPin(),
                                "set pin for further tests");
  int initial_counter = GetPinRetries();
  command_state_->AttemptGetAuthToken(test_helpers::BadPin());
  cbor::Value::BinaryValue old_auth_token =
      command_state_->GetCurrentAuthToken();
  // TODO(kaczmarczyck) compare to new token after either replug only or Reset

  command_state_->Reset();

  CheckPinAbsenceByMakeCredential();
  device_tracker_->AssertStatus(command_state_->SetPin(),
                                "set pin for further tests");
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

  command_state_->Reset();
}

void TestSeries::ResetPhysicalPresenceTest() {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  constexpr absl::Duration reset_timeout_duration = absl::Milliseconds(10000);
  absl::Time reset_timeout = absl::Now() + reset_timeout_duration;

  test_helpers::PrintNoTouchPrompt();
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

}  // namespace fido2_tests
