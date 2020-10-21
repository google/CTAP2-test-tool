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
#include "src/tests/test_helpers.h"
#include "src/tests/test_series.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {

void TestSeries::GetAssertionBadParameterTypesTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  std::string rp_id = "get_bad_types.example.com";
  cbor::Value credential_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, false);
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder full_builder;
  full_builder.AddDefaultsForRequiredFields(rp_id);
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
  test_helpers::TestBadParameterTypes(device, device_tracker,
                                      Command::kAuthenticatorGetAssertion,
                                      &full_builder);
}

void TestSeries::GetAssertionMissingParameterTest(DeviceInterface* device,
                                                  DeviceTracker* device_tracker,
                                                  CommandState* command_state) {
  std::string rp_id = "get_missing.example.com";
  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);

  GetAssertionCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(rp_id);
  test_helpers::TestMissingParameters(device, device_tracker,
                                      Command::kAuthenticatorGetAssertion,
                                      &missing_required_builder);
}

void TestSeries::GetAssertionAllowListCredentialDescriptorTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  constexpr GetAssertionParameters kKey = GetAssertionParameters::kAllowList;
  std::string rp_id = absl::StrCat("get_parameter_allow_list.example.com");
  absl::variant<cbor::Value, Status> response;
  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);

  GetAssertionCborBuilder allow_list_builder;
  allow_list_builder.AddDefaultsForRequiredFields(rp_id);
  test_helpers::TestCredentialDescriptorsArrayForCborDepth(
      device, device_tracker, Command::kAuthenticatorGetAssertion,
      &allow_list_builder, static_cast<int>(kKey), rp_id);

  response = test_helpers::MakeTestCredential(device_tracker, command_state,
                                              rp_id, false);

  cbor::Value::ArrayValue credential_descriptor_list;
  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cbor::Value::BinaryValue cred_descriptor_id =
      test_helpers::ExtractCredentialId(absl::get<cbor::Value>(response));
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  allow_list_builder.SetMapEntry(kKey, cbor::Value(credential_descriptor_list));
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, allow_list_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "accept a valid credential descriptor");
}

void TestSeries::GetAssertionExtensionsTest(DeviceInterface* device,
                                            DeviceTracker* device_tracker,
                                            CommandState* command_state) {
  constexpr GetAssertionParameters kKey = GetAssertionParameters::kExtensions;
  std::string rp_id = absl::StrCat("get_parameter", kKey, ".example.com");
  absl::variant<cbor::Value, Status> response;
  cbor::Value credential_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, false);
  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);

  GetAssertionCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(rp_id);
  extensions_builder.SetAllowListCredential(credential_id);
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(kKey, cbor::Value(extensions_map));
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, extensions_builder.GetCbor());
  device_tracker->CheckAndReport(response, "accept a valid extension");
}

void TestSeries::GetAssertionOptionsTest(DeviceInterface* device,
                                         DeviceTracker* device_tracker,
                                         CommandState* command_state) {
  std::string rp_id = "options.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);
  GetAssertionCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("rk")] = cbor::Value(false);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(authenticator_options));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, options_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrInvalidOption, returned_status,
      "reject invalid residential key option (false)");

  authenticator_options[cbor::Value("rk")] = cbor::Value(true);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(authenticator_options));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, options_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrInvalidOption, returned_status,
      "reject invalid residential key option (true)");

  options_builder.SetUserPresenceOptions(false);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize user presence option (false)");

  options_builder.SetUserPresenceOptions(true);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize user presence option (true)");

  options_builder.SetUserVerificationOptions(false);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize user verification option (false)");

  options_builder.SetUserVerificationOptions(true);
  if (device_tracker->HasOption("clientPin")) {
    if (!device_tracker->HasOption("uv")) {
      device_tracker->AssertStatus(command_state->GetAuthToken(),
                                   "get auth token for further tests");
      options_builder.SetDefaultPinUvAuthParam(
          command_state->GetCurrentAuthToken());
      options_builder.SetDefaultPinUvAuthProtocol();
    }
    response = fido2_commands::GetAssertionPositiveTest(
        device, device_tracker, options_builder.GetCbor());
    device_tracker->CheckAndReport(response,
                                   "recognize user verification option (true)");
    options_builder.RemoveMapEntry(GetAssertionParameters::kPinUvAuthParam);
    options_builder.RemoveMapEntry(GetAssertionParameters::kPinUvAuthProtocol);
    command_state->Reset();
    test_helpers::MakeTestCredential(device_tracker, command_state, rp_id,
                                     true);
  } else {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device, options_builder.GetCbor(), false);
    device_tracker->CheckAndReport(
        Status::kErrInvalidOption, returned_status,
        "recognize user verification option (true) without PIN set");
  }

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(GetAssertionParameters::kOptions,
                              cbor::Value(options_map));
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response, "ignore unknown options");
}

void TestSeries::GetAssertionResidentialKeyTest(DeviceInterface* device,
                                                DeviceTracker* device_tracker,
                                                CommandState* command_state) {
  std::string rp_id = "residential.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  GetAssertionCborBuilder assertion_builder;
  assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "there should be no credentials for this relying party");

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);

  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, assertion_builder.GetCbor());
  device_tracker->CheckAndReport(response, "get assertion for residential key");

  rp_id = "non-residential.example.com";
  assertion_builder.SetRelyingParty(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrNoCredentials, returned_status,
      "there should be no credentials for this relying party");

  cbor::Value credential_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, false);

  cbor::Value::BinaryValue credential_id =
      test_helpers::ExtractCredentialId(credential_response);
  assertion_builder.SetAllowListCredential(credential_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, assertion_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "get assertion for non-residental key");

  cbor::Value::BinaryValue fake_credential_id =
      cbor::Value::BinaryValue(credential_id.size(), 0xFA);
  assertion_builder.SetAllowListCredential(fake_credential_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, assertion_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrNoCredentials, returned_status,
                                 "this credential ID is fake");
}

void TestSeries::GetAssertionPinAuthTest(DeviceInterface* device,
                                         DeviceTracker* device_tracker,
                                         CommandState* command_state) {
  std::string rp_id = "pinauth.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);

  GetAssertionCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device, pin_auth_builder.GetCbor(), true);
    device_tracker->CheckAndReport(
        Status::kErrPinNotSet, returned_status,
        "PIN auth param has zero length, no PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(GetAssertionParameters::kPinUvAuthProtocol,
                               cbor::Value(123456));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                 "pin protocol is not supported");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinNotSet, returned_status,
                                 "pin not set yet");

  device_tracker->AssertStatus(command_state->GetAuthToken(),
                               "get auth token for further tests");
  // Sets a PIN if necessary. From here on, the PIN is set on the authenticator.

  pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, pin_auth_builder.GetCbor());
  device_tracker->CheckAndReport(response, "get assertion using PIN token");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    returned_status = fido2_commands::GetAssertionNegativeTest(
        device, pin_auth_builder.GetCbor(), true);
    device_tracker->CheckAndReport(
        Status::kErrPinInvalid, returned_status,
        "PIN auth param has zero length, but PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                 "pin auth does not match client data hash");

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);

  GetAssertionCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, no_pin_auth_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "get assertion with a PIN set, but without a token");

  no_pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrMissingParameter, returned_status,
      "PIN protocol not given, but PIN auth param is");

  command_state->Reset();
}

void TestSeries::GetAssertionPhysicalPresenceTest(DeviceInterface* device,
                                                  DeviceTracker* device_tracker,
                                                  CommandState* command_state) {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  test_helpers::MakeTestCredential(device_tracker, command_state, rp_id, true);
  test_helpers::PrintNoTouchPrompt();

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, get_assertion_builder.GetCbor(), true);
  device_tracker->CheckAndReport(Status::kErrUserActionTimeout, returned_status,
                                 "key was not touched for get assertion");

  // TODO(kaczmarczyck) ask user for confirmation of flashing LED?
}

// TODO(kaczmarczyck) check returned signature crypto

}  // namespace fido2_tests
