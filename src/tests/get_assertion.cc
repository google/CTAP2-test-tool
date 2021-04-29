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

#include "src/tests/get_assertion.h"

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/types/variant.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/fido2_commands.h"
#include "src/tests/test_helpers.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

GetAssertionBadParameterTypesTest::GetAssertionBadParameterTypesTest()
    : BaseTest("get_assertion_bad_parameter_types",
               "Tests if GetAssertion works with parameters of the wrong type.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), false);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder full_builder;
  full_builder.AddDefaultsForRequiredFields(RpId());
  full_builder.SetAllowListCredential(credential_id);
  full_builder.SetMapEntry(GetAssertionParameters::kExtensions,
                           cbor::Value(cbor::Value::MapValue()));

  cbor::Value::MapValue options;
  // "rk" is an invalid option here.
  options[cbor::Value("up")] = cbor::Value(false);
  options[cbor::Value("uv")] = cbor::Value(false);
  full_builder.SetMapEntry(GetAssertionParameters::kOptions,
                           cbor::Value(options));

  full_builder.SetDefaultPinUvAuthParam(cbor::Value::BinaryValue());
  full_builder.SetDefaultPinUvAuthProtocol();
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorGetAssertion,
      &full_builder);
}

GetAssertionMissingParameterTest::GetAssertionMissingParameterTest()
    : BaseTest("get_assertion_missing_parameter",
               "Tests if GetAssertion works with missing parameters.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(RpId());
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorGetAssertion,
      &missing_required_builder);
}

GetAssertionAllowListCredentialDescriptorTest::
    GetAssertionAllowListCredentialDescriptorTest()
    : BaseTest(
          "get_assertion_allow_list_credential_descriptor",
          "Tests credential descriptors in the allow list of GetAssertion.",
          {.has_pin = false}, {}) {}

std::optional<std::string>
GetAssertionAllowListCredentialDescriptorTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), true);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder allow_list_builder;
  allow_list_builder.AddDefaultsForRequiredFields(RpId());
  cbor::Value::ArrayValue credential_descriptor_list;
  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(credential_id);
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  allow_list_builder.SetMapEntry(GetAssertionParameters::kAllowList,
                                 cbor::Value(credential_descriptor_list));
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, allow_list_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Failure to accept a valid credential descriptor.";
  }
  return std::nullopt;
}

GetAssertionExtensionsTest::GetAssertionExtensionsTest()
    : BaseTest("get_assertion_extensions",
               "Tests if unknown extensions are ignored in GetAssertion.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionExtensionsTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), false);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(RpId());
  extensions_builder.SetAllowListCredential(credential_id);
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(GetAssertionParameters::kExtensions,
                                 cbor::Value(extensions_map));
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, extensions_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Failure to accept a valid extension.";
  }
  return std::nullopt;
}

GetAssertionOptionRkTest::GetAssertionOptionRkTest()
    : BaseTest("get_assertion_option_rk",
               "Tests if the resident key option is rejected in GetAssertion.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionOptionRkTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("rk")] = cbor::Value(false);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(authenticator_options));
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, options_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrInvalidOption,
                                   returned_status)) {
    return "The resident key option (false) was not rejected.";
  }

  authenticator_options[cbor::Value("rk")] = cbor::Value(true);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(authenticator_options));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, options_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrInvalidOption,
                                   returned_status)) {
    return "The resident key option (true) was not rejected.";
  }
  return std::nullopt;
}

GetAssertionOptionUpTest::GetAssertionOptionUpTest()
    : BaseTest(
          "get_assertion_option_up",
          "Tests if the user presence option is supported in GetAssertion.",
          {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionOptionUpTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserPresenceOptions(false);
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user presence option (false) was not accepted.";
  }

  options_builder.SetUserPresenceOptions(true);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user presence option (true) was not accepted.";
  }
  return std::nullopt;
}

GetAssertionOptionUvFalseTest::GetAssertionOptionUvFalseTest()
    : BaseTest("get_assertion_option_uv_false",
               "Tests if user verification set to false is accepted in "
               "GetAssertion.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionOptionUvFalseTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserVerificationOptions(false);
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user verification option (false) was not accepted.";
  }
  return std::nullopt;
}

GetAssertionOptionUvTrueTest::GetAssertionOptionUvTrueTest()
    : BaseTest(
          "get_assertion_option_uv_true",
          "Tests is user verification set to true is accepted in GetAssertion.",
          {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionOptionUvTrueTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserVerificationOptions(true);
  options_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  options_builder.SetDefaultPinUvAuthProtocol();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user verification option (true) was not accepted.";
  }
  return std::nullopt;
}

GetAssertionOptionUnknownTest::GetAssertionOptionUnknownTest()
    : BaseTest("get_assertion_option_unknown",
               "Tests if unknown options are ignored in GetAssertion.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionOptionUnknownTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(options_map));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Falsely rejected unknown option.";
  }
  return std::nullopt;
}

GetAssertionResidentKeyTest::GetAssertionResidentKeyTest()
    : BaseTest("get_assertion_resident_key",
               "Tests if assertions with resident keys work.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionResidentKeyTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  GetAssertionCborBuilder assertion_builder;
  assertion_builder.AddDefaultsForRequiredFields(RpId());
  // TODO(#16) resolve backwards incompatible user presence precedence
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(),
      !test_helpers::IsFido2Point1Complicant(device_tracker));
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "There should be no credentials for this relying party.";
  }

  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "GetAssertion failed for for resident key.";
  }
  return std::nullopt;
}

GetAssertionNonResidentKeyTest::GetAssertionNonResidentKeyTest()
    : BaseTest("get_assertion_non_resident_key",
               "Tests if assertions with non-resident keys work.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionNonResidentKeyTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  GetAssertionCborBuilder assertion_builder;
  assertion_builder.AddDefaultsForRequiredFields(RpId());
  // TODO(#16) resolve backwards incompatible user presence precedence
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(),
      !test_helpers::IsFido2Point1Complicant(device_tracker));
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "There should be no credentials for this relying party.";
  }

  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), false);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "GetAssertion failed for non-resident key.";
  }

  cbor::Value::BinaryValue fake_credential_id =
      cbor::Value::BinaryValue(credential_id.size(), 0xFA);
  assertion_builder.SetAllowListCredential(fake_credential_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "A fake credential ID was not rejected.";
  }
  return std::nullopt;
}

GetAssertionPinAuthEmptyTest::GetAssertionPinAuthEmptyTest()
    : BaseTest("get_assertion_pin_auth_empty",
               "Tests the response on an empty PIN auth without a PIN in "
               "GetAssertion.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthEmptyTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrPinNotSet, returned_status)) {
    return "A zero length PIN auth param is not rejected.";
  }
  return std::nullopt;
}

GetAssertionPinAuthProtocolTest::GetAssertionPinAuthProtocolTest()
    : BaseTest(
          "get_assertion_pin_auth_protocol",
          "Tests if the PIN protocol parameter is checked in GetAssertion.",
          {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthProtocolTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(GetAssertionParameters::kPinUvAuthProtocol,
                               cbor::Value(123456));
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinAuthInvalid,
                                   returned_status)) {
    return "Unsupported PIN protocol is not rejected.";
  }

  return std::nullopt;
}

GetAssertionPinAuthNoPinTest::GetAssertionPinAuthNoPinTest()
    : BaseTest(
          "get_assertion_pin_auth_no_pin",
          "Tests if a PIN auth is rejected without a PIN set in GetAssertion.",
          {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthNoPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinNotSet, returned_status)) {
    return "PIN auth not rejected without a PIN.";
  }
  return std::nullopt;
}

GetAssertionPinAuthEmptyWithPinTest::GetAssertionPinAuthEmptyWithPinTest()
    : BaseTest(
          "get_assertion_pin_auth_empty_with_pin",
          "Tests the response on an empty PIN auth with a PIN in GetAssertion.",
          {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthEmptyWithPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
    return "A zero length PIN auth param is not rejected with a PIN set.";
  }
  return std::nullopt;
}

GetAssertionPinAuthTest::GetAssertionPinAuthTest()
    : BaseTest("get_assertion_pin_auth",
               "Tests if the PIN auth is correctly checked with a PIN set in "
               "GetAssertion.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               pin_auth_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Falsely rejected valid PIN auth.";
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinAuthInvalid,
                                   returned_status)) {
    return "Accepted wrong PIN auth.";
  }
  return std::nullopt;
}

GetAssertionPinAuthMissingParameterTest::
    GetAssertionPinAuthMissingParameterTest()
    : BaseTest(
          "get_assertion_pin_auth_missing_parameter",
          "Tests if client PIN fails with missing parameters in GetAssertion.",
          {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> GetAssertionPinAuthMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }

  GetAssertionCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  no_pin_auth_builder.SetDefaultPinUvAuthProtocol();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::GetAssertionPositiveTest(device, device_tracker,
                                               no_pin_auth_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "GetAssertion failed with PIN protocol, but without a token when "
           "PIN is set.";
  }

  no_pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  no_pin_auth_builder.RemoveMapEntry(
      GetAssertionParameters::kPinUvAuthProtocol);
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrMissingParameter,
                                   returned_status)) {
    return "Missing PIN protocol was not rejected when PIN is set.";
  }

  command_state->Reset();
  return std::nullopt;
}

GetAssertionPhysicalPresenceTest::GetAssertionPhysicalPresenceTest()
    : BaseTest("get_assertion_physical_presence",
               "Tests if user touch is required for GetAssertion.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionPhysicalPresenceTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  if (!device_tracker->CheckStatus(
          command_state->MakeTestCredential(RpId(), true))) {
    return "Cannot make credential for further tests.";
  }
  device_tracker->IgnoreNextTouchPrompt();
  test_helpers::PrintNoTouchPrompt();

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(RpId());
  Status returned_status = fido2_commands::GetAssertionNegativeTest(
      device, get_assertion_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrUserActionTimeout,
                                   returned_status)) {
    return "A credential was asserted without user presence.";
  }
  return std::nullopt;
}

GetAssertionEmptyUserIdTest::GetAssertionEmptyUserIdTest()
    : BaseTest("get_assertion_empty_user_id",
               "Tests if empty user IDs are omitted in the response.",
               {.has_pin = false}, {}) {}

std::optional<std::string> GetAssertionEmptyUserIdTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder empty_id_builder;
  empty_id_builder.AddDefaultsForRequiredFields(RpId());
  empty_id_builder.SetPublicKeyCredentialUserEntity({}, "Emma");
  empty_id_builder.SetResidentKeyOptions(true);
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 empty_id_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential with an empty user ID.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(RpId());
  get_assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, get_assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Unable to assert a credential with empty user ID.";
  }

  cbor::Value assertion_response = std::move(absl::get<cbor::Value>(response));
  const auto& decoded_map = assertion_response.GetMap();
  auto map_iter = decoded_map.find(CborInt(GetAssertionResponse::kUser));
  if (map_iter != decoded_map.end()) {
    return "The response includes user with an empty ID. This behaviour has "
           "known interoperability hurdles.";
  }
  return std::nullopt;
}

// TODO(kaczmarczyck) check returned signature crypto

}  // namespace fido2_tests

