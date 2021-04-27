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

#include "src/tests/client_pin.h"

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/types/variant.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/crypto_utility.h"
#include "src/fido2_commands.h"
#include "src/tests/test_helpers.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace {

constexpr int kWrongPinsBeforePowerCycle = 3;

// This is an example of an EC cose key map for client PIN operations.
static const auto* const kCoseKeyExample =
    new cbor::Value::MapValue(crypto_utility::GenerateExampleEcdhCoseKey());

const cbor::Value::BinaryValue& GetTooShortPaddedPin() {
  static const auto* const pin = [] {
    auto* too_short_pin = new cbor::Value::BinaryValue({0x31, 0x32, 0x33});
    too_short_pin->resize(64, 0x00);
    return too_short_pin;
  }();
  return *pin;
}

const cbor::Value::BinaryValue& GetTooLongPaddedPin() {
  static const auto* const too_long_padded_pin =
      new cbor::Value::BinaryValue(64, 0x30);
  return *too_long_padded_pin;
}

const cbor::Value::BinaryValue& GetMaximumPinUtf8() {
  static const auto* const maximum_pin_utf8 =
      new cbor::Value::BinaryValue(63, 0x30);
  return *maximum_pin_utf8;
}

const cbor::Value::BinaryValue& GetTooShortPadding() {
  static const auto* const pin = [] {
    auto* too_short_padding =
        new cbor::Value::BinaryValue({0x31, 0x32, 0x33, 0x34});
    too_short_padding->resize(32, 0x00);
    return too_short_padding;
  }();
  return *pin;
}

const cbor::Value::BinaryValue& GetTooLongPadding() {
  static const auto* const pin = [] {
    auto* too_long_padding =
        new cbor::Value::BinaryValue({0x31, 0x32, 0x33, 0x34});
    too_long_padding->resize(128, 0x00);
    return too_long_padding;
  }();
  return *pin;
}

// Checks if the PIN is not currently set by trying to make a credential.
// The MakeCredential command should fail when the authenticator is PIN
// protected. Even though this test could fail in case of a bad implementation
// of Make Credential, this kind of misbehavior would be caught in another
// test.
std::optional<std::string> CheckPinAbsenceByMakeCredential(
    DeviceInterface* device, DeviceTracker* device_tracker) {
  MakeCredentialCborBuilder test_builder;
  test_builder.AddDefaultsForRequiredFields("pin_absence.example.com");
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 test_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "MakeCredential failed, potentially because an undesired PIN "
           "exists.";
  }
  return std::nullopt;
}

// Checks if the PIN we currently assume is set works for getting an auth
// token. This way, we don't have to trust only the returned status code
// after a SetPin or ChangePin command.
std::optional<std::string> CheckPinByGetAuthToken(DeviceTracker* device_tracker,
                                                  CommandState* command_state) {
  if (!device_tracker->CheckStatus(command_state->GetAuthToken(false))) {
    return "GetAuthToken failed, potentially because the assumed PIN does not "
           "exist.";
  }
  return std::nullopt;
}

}  // namespace

GetPinRetriesBadParameterTypesTest::GetPinRetriesBadParameterTypesTest()
    : BaseTest(
          "client_pin_get_pin_retries_bad_parameter_types",
          "Tests if GetPinRetries works with parameters of the wrong type.",
          {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetPinRetriesBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinRetries();
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetPinRetriesMissingParameterTest::GetPinRetriesMissingParameterTest()
    : BaseTest("client_pin_get_pin_retries_missing_parameter",
               "Tests if GetPinRetries works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetPinRetriesMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinRetries();
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetKeyAgreementBadParameterTypesTest::GetKeyAgreementBadParameterTypesTest()
    : BaseTest(
          "client_pin_get_key_agreement_bad_parameter_types",
          "Tests if GetKeyAgreement works with parameters of the wrong type.",
          {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetKeyAgreementBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetKeyAgreement();
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetKeyAgreementMissingParameterTest::GetKeyAgreementMissingParameterTest()
    : BaseTest("client_pin_get_key_agreement_missing_parameter",
               "Tests if GetKeyAgreement works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetKeyAgreementMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetKeyAgreement();
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

SetPinBadParameterTypesTest::SetPinBadParameterTypesTest()
    : BaseTest("client_pin_set_pin_bad_parameter_types",
               "Tests if SetPin works with parameters of the wrong type.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> SetPinBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForSetPin(*kCoseKeyExample, cbor::Value::BinaryValue(),
                                   cbor::Value::BinaryValue());
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

SetPinMissingParameterTest::SetPinMissingParameterTest()
    : BaseTest("client_pin_set_pin_missing_parameter",
               "Tests if SetPin works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> SetPinMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForSetPin(*kCoseKeyExample, cbor::Value::BinaryValue(),
                                   cbor::Value::BinaryValue());
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

ChangePinBadParameterTypesTest::ChangePinBadParameterTypesTest()
    : BaseTest("client_pin_change_pin_bad_parameter_types",
               "Tests if ChangePin works with parameters of the wrong type.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> ChangePinBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForChangePin(
      *kCoseKeyExample, cbor::Value::BinaryValue(), cbor::Value::BinaryValue(),
      cbor::Value::BinaryValue());
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

ChangePinMissingParameterTest::ChangePinMissingParameterTest()
    : BaseTest("client_pin_change_pin_missing_parameter",
               "Tests if ChangePin works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> ChangePinMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForChangePin(
      *kCoseKeyExample, cbor::Value::BinaryValue(), cbor::Value::BinaryValue(),
      cbor::Value::BinaryValue());
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetPinTokenBadParameterTypesTest::GetPinTokenBadParameterTypesTest()
    : BaseTest("client_pin_get_pin_token_bad_parameter_types",
               "Tests if GetPinToken works with parameters of the wrong type.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetPinTokenBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinToken(*kCoseKeyExample,
                                        cbor::Value::BinaryValue());
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetPinTokenMissingParameterTest::GetPinTokenMissingParameterTest()
    : BaseTest("client_pin_get_token_missing_parameter",
               "Tests if GetPinToken works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetPinTokenMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinToken(*kCoseKeyExample,
                                        cbor::Value::BinaryValue());
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetPinUvAuthTokenUsingUvWithPermissionsBadParameterTypesTest::
    GetPinUvAuthTokenUsingUvWithPermissionsBadParameterTypesTest()
    : BaseTest(
          "client_pin_get_pin_uv_auth_token_using_uv_with_permissions_bad_"
          "parameter_types",
          "Tests if GetPinUvAuthTokenUsingUvWithPermissions works with "
          "parameters of the "
          "wrong type.",
          {.has_pin = false}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string>
GetPinUvAuthTokenUsingUvWithPermissionsBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinUvAuthTokenUsingUvWithPermissions(
      *kCoseKeyExample);
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetPinUvAuthTokenUsingUvWithPermissionsMissingParameterTest::
    GetPinUvAuthTokenUsingUvWithPermissionsMissingParameterTest()
    : BaseTest(
          "client_pin_get_pin_uv_auth_token_using_uv_with_permissions_missing_"
          "parameter",
          "Tests if GetPinUvAuthTokenUsingUvWithPermissions works with missing "
          "parameters.",
          {.has_pin = false}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string>
GetPinUvAuthTokenUsingUvWithPermissionsMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetPinUvAuthTokenUsingUvWithPermissions(
      *kCoseKeyExample);
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetUVRetriesBadParameterTypesTest::GetUVRetriesBadParameterTypesTest()
    : BaseTest("client_pin_get_uv_retries_bad_parameter_types",
               "Tests if GetUVRetries works with parameters of the wrong type.",
               {.has_pin = false}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string> GetUVRetriesBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetUvRetries();
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

GetUVRetriesMissingParameterTest::GetUVRetriesMissingParameterTest()
    : BaseTest("client_pin_get_uv_retries_missing_parameter",
               "Tests if GetUVRetries works with missing parameters.",
               {.has_pin = false}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string> GetUVRetriesMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  AuthenticatorClientPinCborBuilder pin_builder;
  pin_builder.AddDefaultsForGetUvRetries();
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorClientPIN, &pin_builder);
}

ClientPinRequirementsSetPinTest::ClientPinRequirementsSetPinTest()
    : BaseTest("client_pin_requirements_set_pin",
               "Tests if PIN requirement are enforced in SetPin.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> ClientPinRequirementsSetPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // The minimum length is 4, but the authenticator can enforce more, so only
  // testing the maximum length here.
  // TODO(kaczmarczyck) use minimum PIN length from GetInfo here and below
  Status returned_status = command_state->AttemptSetPin(GetTooShortPaddedPin());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with length < 4.";
  }
  NONE_OR_RETURN(CheckPinAbsenceByMakeCredential(device, device_tracker));

  returned_status = command_state->AttemptSetPin(GetTooLongPaddedPin());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with length > 63.";
  }
  NONE_OR_RETURN(CheckPinAbsenceByMakeCredential(device, device_tracker));

  if (!device_tracker->CheckStatus(
          command_state->SetPin(GetMaximumPinUtf8()))) {
    return "Falsely rejected PIN with length 63.";
  }
  return CheckPinByGetAuthToken(device_tracker, command_state);
}

ClientPinRequirementsChangePinTest::ClientPinRequirementsChangePinTest()
    : BaseTest("client_pin_requirements_change_pin",
               "Tests if PIN requirement are enforced in ChangePin.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> ClientPinRequirementsChangePinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // Again only not minimum PIN length, since it might be bigger than 4.
  Status returned_status =
      command_state->AttemptChangePin(GetTooShortPaddedPin());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with length < 4.";
  }
  NONE_OR_RETURN(CheckPinByGetAuthToken(device_tracker, command_state));

  returned_status = command_state->AttemptChangePin(GetTooLongPaddedPin());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with length > 63.";
  }
  NONE_OR_RETURN(CheckPinByGetAuthToken(device_tracker, command_state));

  if (!device_tracker->CheckStatus(
          command_state->ChangePin(GetMaximumPinUtf8()))) {
    return "Falsely rejected PIN with length 63.";
  }
  return CheckPinByGetAuthToken(device_tracker, command_state);
}

ClientPinNewRequirementsSetPinTest::ClientPinNewRequirementsSetPinTest()
    : BaseTest("client_pin_new_requirements_set_pin",
               "Tests if new PIN requirement are enforced in SetPin.",
               {.has_pin = false}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string> ClientPinNewRequirementsSetPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  Status returned_status = command_state->AttemptSetPin(GetTooShortPadding());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with padding of length 32.";
  }
  NONE_OR_RETURN(CheckPinAbsenceByMakeCredential(device, device_tracker));

  returned_status = command_state->AttemptSetPin(GetTooLongPadding());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with padding of length 128.";
  }
  return CheckPinAbsenceByMakeCredential(device, device_tracker);
}

ClientPinNewRequirementsChangePinTest::ClientPinNewRequirementsChangePinTest()
    : BaseTest("client_pin_new_requirements_change_pin",
               "Tests if new PIN requirement are enforced in ChangePin.",
               {.has_pin = true}, {Tag::kClientPin, Tag::kFido2Point1}) {}

std::optional<std::string> ClientPinNewRequirementsChangePinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  Status returned_status =
      command_state->AttemptChangePin(GetTooShortPadding());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with padding of length 32.";
  }
  NONE_OR_RETURN(CheckPinByGetAuthToken(device_tracker, command_state));

  returned_status = command_state->AttemptChangePin(GetTooLongPadding());
  if (!device_tracker->CheckStatus(Status::kErrPinPolicyViolation,
                                   returned_status)) {
    return "Accepted a PIN with padding of length 128.";
  }
  return CheckPinByGetAuthToken(device_tracker, command_state);
}

ClientPinOldKeyMaterialTest::ClientPinOldKeyMaterialTest()
    : BaseTest("client_pin_old_key_material",
               "Tests if key material is regenerated correctly.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> ClientPinOldKeyMaterialTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // Reuses key material that should have been renewed to see if it still works.
  Status returned_status = command_state->AttemptGetAuthToken(
      test_helpers::BadPin(device_tracker->GetMinPinLength()), false);
  if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
    return "A wrong PIN was not rejected.";
  }
  returned_status = command_state->AttemptGetAuthToken();
  if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
    return "The correct PIN with an old shared secret was not rejected.";
  }
  return std::nullopt;
}

ClientPinGeneralPinRetriesTest::ClientPinGeneralPinRetriesTest()
    : BaseTest("client_pin_general_pin_retries",
               "Tests if PIN retries are decreased and reset.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> ClientPinGeneralPinRetriesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // Prior tests might have messed with the retry counter. Reset it.
  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed unexpectedly.";
  }

  auto initial_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(initial_counter)) {
    return absl::get<std::string>(initial_counter);
  }
  int max_retries = absl::get<int>(initial_counter);
  if (max_retries > 8) {
    return "Maximum PIN retries exceed the upper limit of 8.";
  }
  if (max_retries <= 0) {
    return "Maximum PIN retries is not a positive number.";
  }
  auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries) {
    return "PIN retries changed between subsequent calls.";
  }

  Status returned_status = command_state->AttemptGetAuthToken(
      test_helpers::BadPin(device_tracker->GetMinPinLength()));
  if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
    return "A wrong PIN was not rejected.";
  }
  new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries - 1) {
    return "PIN retries did not decrement after a failed attempt.";
  }

  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed unexpectedly.";
  }
  new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries) {
    return "PIN retries did not reset after entering the correct PIN.";
  }
  return std::nullopt;
}

ClientPinAuthBlockPinRetriesTest::ClientPinAuthBlockPinRetriesTest()
    : BaseTest("client_pin_auth_block_pin_retries",
               "Tests if PIN auth attempts are blocked correctly.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> ClientPinAuthBlockPinRetriesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // Prior tests might have messed with the retry counter. Reset it.
  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed unexpectedly.";
  }

  auto initial_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(initial_counter)) {
    return absl::get<std::string>(initial_counter);
  }
  int max_retries = absl::get<int>(initial_counter);
  if (max_retries <= kWrongPinsBeforePowerCycle) {
    device_tracker->AddObservation(
        absl::StrCat("PIN auth block replugging untested, since only ",
                     max_retries, " are allowed."));
    return std::nullopt;
  }

  for (int attempts = 1; attempts < kWrongPinsBeforePowerCycle; ++attempts) {
    Status returned_status = command_state->AttemptGetAuthToken(
        test_helpers::BadPin(device_tracker->GetMinPinLength()));
    if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
      return "A wrong PIN was not rejected.";
    }
  }
  Status returned_status = command_state->AttemptGetAuthToken(
      test_helpers::BadPin(device_tracker->GetMinPinLength()));
  if (!device_tracker->CheckStatus(Status::kErrPinAuthBlocked,
                                   returned_status)) {
    return "A wrong PIN was not blocked.";
  }
  auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries - kWrongPinsBeforePowerCycle) {
    return "PIN retries did not decrement before auth was block.";
  }

  returned_status = command_state->AttemptGetAuthToken();
  if (!device_tracker->CheckStatus(Status::kErrPinAuthBlocked,
                                   returned_status)) {
    return "The correct PIN is not blocked when auth is blocked.";
  }
  new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries - kWrongPinsBeforePowerCycle) {
    return "PIN retries decremented on a blocked attempt.";
  }

  command_state->PromptReplugAndInit();
  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed after replugging an auth block.";
  }
  new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != max_retries) {
    return "PIN retries did not reset after entering the correct PIN.";
  }
  return std::nullopt;
}

ClientPinBlockPinRetriesTest::ClientPinBlockPinRetriesTest()
    : BaseTest("client_pin_block_pin_retries",
               "Tests if PINs are blocked correctly.", {.has_pin = true},
               {Tag::kClientPin}) {}

std::optional<std::string> ClientPinBlockPinRetriesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  // Prior tests might have messed with the retry counter. Reset it.
  if (!device_tracker->CheckStatus(command_state->GetAuthToken())) {
    return "Getting the auth token failed unexpectedly.";
  }

  auto initial_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(initial_counter)) {
    return absl::get<std::string>(initial_counter);
  }
  int max_retries = absl::get<int>(initial_counter);

  // Leaves one attempt.
  for (int attempts = 1; attempts < max_retries; ++attempts) {
    Status returned_status = command_state->AttemptGetAuthToken(
        test_helpers::BadPin(device_tracker->GetMinPinLength()));
    if (attempts % kWrongPinsBeforePowerCycle != 0) {
      // Normal case, PIN not blocked.
      if (!device_tracker->CheckStatus(Status::kErrPinInvalid,
                                       returned_status)) {
        return "A wrong PIN was not rejected.";
      }
    } else {
      // Needs replug before more attempts.
      if (!device_tracker->CheckStatus(Status::kErrPinAuthBlocked,
                                       returned_status)) {
        return "A wrong PIN was not blocked.";
      }
      command_state->PromptReplugAndInit();
    }
    auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
    if (absl::holds_alternative<std::string>(new_counter)) {
      return absl::get<std::string>(new_counter);
    }
    if (absl::get<int>(new_counter) != max_retries - attempts) {
      return "PIN retries did not decrement correctly.";
    }
  }

  Status returned_status = command_state->AttemptGetAuthToken(
      test_helpers::BadPin(device_tracker->GetMinPinLength()));
  if (!device_tracker->CheckStatus(Status::kErrPinBlocked, returned_status)) {
    return "The PIN is not blocked after the counter reached 0.";
  }
  auto new_counter = test_helpers::GetPinRetries(device, device_tracker);
  if (absl::holds_alternative<std::string>(new_counter)) {
    return absl::get<std::string>(new_counter);
  }
  if (absl::get<int>(new_counter) != 0) {
    return "PIN retries did not decrement to 0.";
  }
  returned_status = command_state->AttemptGetAuthToken();
  if (!device_tracker->CheckStatus(Status::kErrPinBlocked, returned_status)) {
    return "The correct PIN is not blocked after using up all retries.";
  }

  command_state->Reset();
  return std::nullopt;
  // TODO(kaczmarczyck) check optional powerCycleState
}

}  // namespace fido2_tests

