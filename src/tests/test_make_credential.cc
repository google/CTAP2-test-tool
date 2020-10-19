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

void TestSeries::MakeCredentialBadParameterTypesTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  std::string rp_id = "make_bad_types.example.com";
  MakeCredentialCborBuilder full_builder;

  full_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("name")] = cbor::Value("example");
  pub_key_cred_rp_entity[cbor::Value("icon")] = cbor::Value("http://icon.png");
  full_builder.SetMapEntry(MakeCredentialParameters::kRp,
                           cbor::Value(pub_key_cred_rp_entity));

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("John Doe");
  pub_key_cred_user_entity[cbor::Value("icon")] =
      cbor::Value("http://icon.png");
  pub_key_cred_user_entity[cbor::Value("displayName")] = cbor::Value("JD");
  full_builder.SetMapEntry(MakeCredentialParameters::kUser,
                           cbor::Value(pub_key_cred_user_entity));

  full_builder.SetExcludeListCredential(cbor::Value::BinaryValue());
  full_builder.SetMapEntry(MakeCredentialParameters::kExtensions,
                           cbor::Value(cbor::Value::MapValue()));

  cbor::Value::MapValue options;
  options[cbor::Value("rk")] = cbor::Value(false);
  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    options[cbor::Value("up")] = cbor::Value(false);
  }
  options[cbor::Value("uv")] = cbor::Value(false);
  full_builder.SetMapEntry(MakeCredentialParameters::kOptions,
                           cbor::Value(options));

  full_builder.SetDefaultPinUvAuthParam(cbor::Value::BinaryValue());
  full_builder.SetDefaultPinUvAuthProtocol();
  test_helpers::TestBadParameterTypes(device, device_tracker,
                                      Command::kAuthenticatorMakeCredential,
                                      &full_builder);
}

void TestSeries::MakeCredentialMissingParameterTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  std::string rp_id = "make_missing.example.com";
  MakeCredentialCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(rp_id);
  test_helpers::TestMissingParameters(device, device_tracker,
                                      Command::kAuthenticatorMakeCredential,
                                      &missing_required_builder);

  // TODO(kaczmarczyck) maybe allow more different errors?
  // For a missing key 4, the Yubikey sends a kErrUnsupportedAlgorithm instead
  // of kErrMissingParameter, which would be correct for an empty list, but here
  // the list is missing entirely.
}

void TestSeries::MakeCredentialRelyingPartyEntityTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  constexpr MakeCredentialParameters kKey = MakeCredentialParameters::kRp;
  std::string rp_id = absl::StrCat("make_parameter_rp.example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder rp_entity_builder;
  rp_entity_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("name")] = cbor::Value("example");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, rp_entity_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "recognize optional name in relying party entity");

  pub_key_cred_rp_entity.clear();
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  pub_key_cred_rp_entity[cbor::Value("icon")] = cbor::Value("http://icon.png");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, rp_entity_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "recognize optional icon in relying party entity");
}

void TestSeries::MakeCredentialUserEntityTest(DeviceInterface* device,
                                              DeviceTracker* device_tracker,
                                              CommandState* command_state) {
  constexpr MakeCredentialParameters kKey = MakeCredentialParameters::kUser;
  std::string rp_id = absl::StrCat("make_parameter_user.example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder user_entity_builder;
  user_entity_builder.AddDefaultsForRequiredFields(rp_id);

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize optional name in user entity");

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("icon")] =
      cbor::Value("http://icon.png");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize optional icon in user entity");

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("displayName")] = cbor::Value("A L");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "recognize optional displayName in user entity");
}

void TestSeries::MakeCredentialExcludeListCredentialDescriptorTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  constexpr MakeCredentialParameters kKey =
      MakeCredentialParameters::kExcludeList;
  std::string rp_id = absl::StrCat("make_parameter_exclude_list.example.com");
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(rp_id);
  test_helpers::TestCredentialDescriptorsArrayForCborDepth(
      device, device_tracker, Command::kAuthenticatorMakeCredential,
      &exclude_list_builder, static_cast<int>(kKey), rp_id);

  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cbor::Value::BinaryValue cred_descriptor_id(32, 0xce);
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  cbor::Value::ArrayValue credential_descriptor_list;
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  exclude_list_builder.SetMapEntry(kKey,
                                   cbor::Value(credential_descriptor_list));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, exclude_list_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "accept a valid credential descriptor");
}

void TestSeries::MakeCredentialExtensionsTest(DeviceInterface* device,
                                              DeviceTracker* device_tracker,
                                              CommandState* command_state) {
  constexpr MakeCredentialParameters kKey =
      MakeCredentialParameters::kExtensions;
  std::string rp_id = absl::StrCat("make_parameter_extensions.example.com");

  MakeCredentialCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(rp_id);
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(kKey, cbor::Value(extensions_map));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 extensions_builder.GetCbor());
  device_tracker->CheckAndReport(response, "accept valid extension");
}

void TestSeries::MakeCredentialExcludeListTest(DeviceInterface* device,
                                               DeviceTracker* device_tracker,
                                               CommandState* command_state) {
  std::string rp_id = "exclude.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  cbor::Value credential_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, true);

  cbor::Value::BinaryValue cred_descriptor_id =
      test_helpers::ExtractCredentialId(credential_response);
  GetAssertionCborBuilder exclude_assertion_builder;
  exclude_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, exclude_assertion_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "get assertion on recently created credential");

  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(rp_id);
  exclude_list_builder.SetResidentialKeyOptions(true);
  exclude_list_builder.SetPublicKeyCredentialUserEntity(
      cbor::Value::BinaryValue(32, 0x02), "Bob");
  exclude_list_builder.SetExcludeListCredential(cred_descriptor_id);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, exclude_list_builder.GetCbor(), true);
  device_tracker->CheckAndReport(
      Status::kErrCredentialExcluded, returned_status,
      "credential descriptor is in the exclude list");

  exclude_list_builder.SetDefaultPublicKeyCredentialRpEntity(
      "another.exclude.example.com");
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, exclude_list_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "make a credential for an unrelated relying party");
}

void TestSeries::MakeCredentialCoseAlgorithmTest(DeviceInterface* device,
                                                 DeviceTracker* device_tracker,
                                                 CommandState* command_state) {
  std::string rp_id = "algorithm.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder cose_algorithm_builder;
  cose_algorithm_builder.AddDefaultsForRequiredFields(rp_id);
  cbor::Value::ArrayValue pub_key_cred_params;
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrUnsupportedAlgorithm,
                                 returned_status,
                                 "credential parameters list is empty");

  cbor::Value::MapValue test_cred_param;
  test_cred_param[cbor::Value("alg")] = cbor::Value(-1);  // unassigned number
  test_cred_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrUnsupportedAlgorithm, returned_status,
      "unsupported algorithm in credential parameters");

  pub_key_cred_params.clear();
  test_cred_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kEs256Algorithm));
  test_cred_param[cbor::Value("type")] = cbor::Value("non-existing type");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrUnsupportedAlgorithm,
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
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, cose_algorithm_builder.GetCbor());
  device_tracker->CheckAndReport(
      response, "accept credential parameter list with 1 good and 1 bad item");
}

void TestSeries::MakeCredentialOptionsTest(DeviceInterface* device,
                                           DeviceTracker* device_tracker,
                                           CommandState* command_state) {
  std::string rp_id = "options.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(rp_id);

  options_builder.SetResidentialKeyOptions(false);
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize resident key option (false)");

  options_builder.SetResidentialKeyOptions(true);
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "recognize resident key option (true)");

  options_builder.SetUserPresenceOptions(false);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, options_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrInvalidOption, returned_status,
                                 "reject user presence option set to false");

  // Option {up: true} was specified ambiguously in CTAP 2.0.
  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    options_builder.SetUserPresenceOptions(true);
    response = fido2_commands::MakeCredentialPositiveTest(
        device, device_tracker, options_builder.GetCbor());
    device_tracker->CheckAndReport(response,
                                   "recognize user presence option (true)");
  }

  options_builder.SetUserVerificationOptions(false);
  response = fido2_commands::MakeCredentialPositiveTest(
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
    response = fido2_commands::MakeCredentialPositiveTest(
        device, device_tracker, options_builder.GetCbor());
    device_tracker->CheckAndReport(response,
                                   "recognize user verification option (true)");
    options_builder.RemoveMapEntry(MakeCredentialParameters::kPinUvAuthParam);
    options_builder.RemoveMapEntry(
        MakeCredentialParameters::kPinUvAuthProtocol);
    command_state->Reset();
  } else {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device, options_builder.GetCbor(), false);
    device_tracker->CheckAndReport(
        Status::kErrInvalidOption, returned_status,
        "recognize user verification option (true) without PIN set");
  }

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(MakeCredentialParameters::kOptions,
                              cbor::Value(options_map));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  device_tracker->CheckAndReport(response, "ignore unknown options");
}

void TestSeries::MakeCredentialPinAuthTest(DeviceInterface* device,
                                           DeviceTracker* device_tracker,
                                           CommandState* command_state) {
  std::string rp_id = "pinauth.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device, pin_auth_builder.GetCbor(), true);
    device_tracker->CheckAndReport(
        Status::kErrPinNotSet, returned_status,
        "PIN auth param has zero length, no PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(MakeCredentialParameters::kPinUvAuthProtocol,
                               cbor::Value(123456));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                 "pin protocol is not supported");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinNotSet, returned_status,
                                 "pin not set yet");

  device_tracker->AssertStatus(command_state->GetAuthToken(),
                               "get auth token for further tests");
  // Sets a PIN if necessary. From here on, the PIN is set on the authenticator.

  pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, pin_auth_builder.GetCbor());
  device_tracker->CheckAndReport(response, "make credential using PIN token");

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device, pin_auth_builder.GetCbor(), true);
    device_tracker->CheckAndReport(
        Status::kErrPinInvalid, returned_status,
        "PIN auth param has zero length, but PIN is set");
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinAuthInvalid, returned_status,
                                 "pin auth does not match client data hash");

  MakeCredentialCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrPinRequired, returned_status,
                                 "PIN parameter not given, but PIN is set");

  // The specification has only a general statement about error codes, so these
  // are just guesses.
  no_pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrPinRequired, returned_status,
      "PIN auth param not given, but PIN protocol is");

  no_pin_auth_builder.RemoveMapEntry(
      MakeCredentialParameters::kPinUvAuthProtocol);
  no_pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  device_tracker->CheckAndReport(
      Status::kErrMissingParameter, returned_status,
      "PIN protocol not given, but PIN auth param is");

  command_state->Reset();
}

void TestSeries::MakeCredentialMultipleKeysTest(DeviceInterface* device,
                                                DeviceTracker* device_tracker,
                                                CommandState* command_state,
                                                int num_credentials) {
  std::string rp_id = "multiple_keys.example.com";
  Status returned_status;

  cbor::Value first_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, true);
  cbor::Value second_response = test_helpers::MakeTestCredential(
      device_tracker, command_state, rp_id, true);

  cbor::Value::BinaryValue first_credential_id =
      test_helpers::ExtractCredentialId(first_response);
  cbor::Value::BinaryValue second_credential_id =
      test_helpers::ExtractCredentialId(second_response);
  device_tracker->CheckAndReport(first_credential_id != second_credential_id,
                                 "the same credential was created twice");

  MakeCredentialCborBuilder residential_key_builder;
  residential_key_builder.AddDefaultsForRequiredFields(rp_id);
  residential_key_builder.SetResidentialKeyOptions(true);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, residential_key_builder.GetCbor(), true);
  uint8_t counter = 0;
  while (returned_status == Status::kErrNone && counter != num_credentials) {
    counter += 1;
    residential_key_builder.SetPublicKeyCredentialUserEntity(
        cbor::Value::BinaryValue(32, counter), "Greedy Greg");
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device, residential_key_builder.GetCbor(), true);
  }
  if (counter != num_credentials) {
    device_tracker->CheckAndReport(
        Status::kErrKeyStoreFull, returned_status,
        "full keystore after creating lots of residential keys");
  } else {
    std::cout << "Omitting to test filling up the key store, over "
              << num_credentials << " keys fit." << std::endl;
  }

  command_state->Reset();
}

void TestSeries::MakeCredentialPhysicalPresenceTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
  // Currently, devices with displays are not supported.
  std::string rp_id = "presence.example.com";
  Status returned_status;
  absl::variant<cbor::Value, Status> response;

  test_helpers::PrintNoTouchPrompt();

  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(rp_id);
  make_credential_builder.SetResidentialKeyOptions(true);
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, make_credential_builder.GetCbor(), true);
  device_tracker->CheckAndReport(Status::kErrUserActionTimeout, returned_status,
                                 "key was not touched for make credential");

  // TODO(kaczmarczcyk) ask user for confirmation of flashing LED?

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(rp_id);
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, get_assertion_builder.GetCbor(), false);
  device_tracker->CheckAndReport(Status::kErrNoCredentials, returned_status,
                                 "the asserted credential shouldn't exist");
}

void TestSeries::MakeCredentialDisplayNameEncodingTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) {
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
    make_credential_builder.SetMapEntry(MakeCredentialParameters::kUser,
                                        cbor::Value(pub_key_cred_user_entity));

    response = fido2_commands::MakeCredentialPositiveTest(
        device, device_tracker, make_credential_builder.GetCbor());
    device_tracker->CheckAndReport(
        response, "accept displayName with non-ASCII characters");
  }

  std::string display_name = "テスト";
  pub_key_cred_user_entity[cbor::Value("displayName")] =
      cbor::Value(display_name);
  make_credential_builder.SetMapEntry(
      MakeCredentialParameters::kUser,
      cbor::Value(std::move(pub_key_cred_user_entity)));

  if (test_helpers::IsFido2Point1Complicant(device_tracker)) {
    auto req_cbor = cbor::Writer::Write(make_credential_builder.GetCbor());
    CHECK(req_cbor.has_value()) << "encoding went wrong - TEST SUITE BUG";

    std::vector<uint8_t> display_name_bytes(display_name.begin(),
                                            display_name.end());
    auto iter =
        std::search(req_cbor->begin(), req_cbor->end(),
                    display_name_bytes.begin(), display_name_bytes.end());
    CHECK(iter != req_cbor->end()) << "encoding problem - TEST SUITE BUG";
    // Generating an invalid UTF-8 encoding here.
    *iter = 0x80;
    returned_status = fido2_commands::NonCborNegativeTest(
        device, *req_cbor, Command::kAuthenticatorMakeCredential, false);
    if (returned_status != Status::kErrInvalidCbor) {
      device_tracker->AddProblem("UTF-8 correctness is not checked.");
    }
  }
}

void TestSeries::MakeCredentialHmacSecretTest(DeviceInterface* device,
                                              DeviceTracker* device_tracker,
                                              CommandState* command_state) {
  if (!device_tracker->HasExtension("hmac-secret")) {
    return;
  }
  std::string rp_id = "hmac-secret.example.com";
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder hmac_secret_builder;
  hmac_secret_builder.AddDefaultsForRequiredFields(rp_id);
  hmac_secret_builder.SetResidentialKeyOptions(true);

  cbor::Value::MapValue extension_map;
  extension_map[cbor::Value("hmac-secret")] = cbor::Value(true);
  hmac_secret_builder.SetMapEntry(MakeCredentialParameters::kExtensions,
                                  cbor::Value(extension_map));

  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, hmac_secret_builder.GetCbor());
  device_tracker->CheckAndReport(response,
                                 "make credential with HMAC-secret extension");
}

}  // namespace fido2_tests
