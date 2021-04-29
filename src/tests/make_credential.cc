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

#include "src/tests/make_credential.h"

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/types/variant.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/fido2_commands.h"
#include "src/tests/test_helpers.h"
#include "third_party/chromium_components_cbor/values.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {

MakeCredentialBadParameterTypesTest::MakeCredentialBadParameterTypesTest()
    : BaseTest(
          "make_credential_bad_parameter_types",
          "Tests if MakeCredential works with parameters of the wrong type.",
          {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialBadParameterTypesTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder full_builder;
  full_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(RpId());
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
  // TODO(#16) resolve backwards incompatible user presence precedence for "up"
  options[cbor::Value("uv")] = cbor::Value(false);
  full_builder.SetMapEntry(MakeCredentialParameters::kOptions,
                           cbor::Value(options));

  full_builder.SetDefaultPinUvAuthParam(cbor::Value::BinaryValue());
  full_builder.SetDefaultPinUvAuthProtocol();
  return test_helpers::TestBadParameterTypes(
      device, device_tracker, Command::kAuthenticatorMakeCredential,
      &full_builder);
}

MakeCredentialMissingParameterTest::MakeCredentialMissingParameterTest()
    : BaseTest("make_credential_missing_parameter",
               "Tests if MakeCredential works with missing parameters.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder missing_required_builder;
  missing_required_builder.AddDefaultsForRequiredFields(RpId());
  return test_helpers::TestMissingParameters(
      device, device_tracker, Command::kAuthenticatorMakeCredential,
      &missing_required_builder);

  // TODO(kaczmarczyck) list of allowed error codes
  // For a missing key 4, the Yubikey sends a kErrUnsupportedAlgorithm instead
  // of kErrMissingParameter, which would be correct for an empty list, but here
  // the list is missing entirely.
}

MakeCredentialRelyingPartyEntityTest::MakeCredentialRelyingPartyEntityTest()
    : BaseTest("make_credential_relying_party_entity",
               "Tests bad parameters in RP entity parameter of MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialRelyingPartyEntityTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  constexpr MakeCredentialParameters kKey = MakeCredentialParameters::kRp;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder rp_entity_builder;
  rp_entity_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(RpId());
  pub_key_cred_rp_entity[cbor::Value("name")] = cbor::Value("example");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, rp_entity_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Optional entry name not recognized.";
  }

  pub_key_cred_rp_entity.clear();
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(RpId());
  pub_key_cred_rp_entity[cbor::Value("icon")] = cbor::Value("http://icon.png");
  rp_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_rp_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, rp_entity_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Optional entry icon not recognized.";
  }
  return std::nullopt;
}

MakeCredentialUserEntityTest::MakeCredentialUserEntityTest()
    : BaseTest("make_credential_user_entity",
               "Tests bad parameters in user parameter of MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialUserEntityTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  constexpr MakeCredentialParameters kKey = MakeCredentialParameters::kUser;
  absl::variant<cbor::Value, Status> response;

  MakeCredentialCborBuilder user_entity_builder;
  user_entity_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Optional entry name not recognized.";
  }

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("icon")] =
      cbor::Value("http://icon.png");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Optional entry icon not recognized.";
  }

  pub_key_cred_user_entity.clear();
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("displayName")] = cbor::Value("A L");
  user_entity_builder.SetMapEntry(kKey, cbor::Value(pub_key_cred_user_entity));
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, user_entity_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Optional entry displayName not recognized.";
  }
  return std::nullopt;
}

MakeCredentialExcludeListCredentialDescriptorTest::
    MakeCredentialExcludeListCredentialDescriptorTest()
    : BaseTest(
          "make_credential_exclude_list_credential_descriptor",
          "Tests credential descriptors in the exclude list of MakeCredential.",
          {.has_pin = false}, {}) {}

std::optional<std::string>
MakeCredentialExcludeListCredentialDescriptorTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue good_cred_descriptor;
  good_cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cbor::Value::BinaryValue cred_descriptor_id(32, 0xce);
  good_cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  cbor::Value::ArrayValue credential_descriptor_list;
  credential_descriptor_list.push_back(cbor::Value(good_cred_descriptor));
  exclude_list_builder.SetMapEntry(MakeCredentialParameters::kExcludeList,
                                   cbor::Value(credential_descriptor_list));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(
          device, device_tracker, exclude_list_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Failure to accept a valid credential descriptor.";
  }
  return std::nullopt;
}

MakeCredentialExtensionsTest::MakeCredentialExtensionsTest()
    : BaseTest("make_credential_extensions",
               "Tests if unknown extensions are ignored in MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialExtensionsTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder extensions_builder;
  extensions_builder.AddDefaultsForRequiredFields(RpId());
  cbor::Value::MapValue extensions_map;
  extensions_map[cbor::Value("test_extension")] = cbor::Value("extension CBOR");
  extensions_builder.SetMapEntry(MakeCredentialParameters::kExtensions,
                                 cbor::Value(extensions_map));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 extensions_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Failure to accept a valid extension.";
  }
  return std::nullopt;
}

MakeCredentialExcludeListTest::MakeCredentialExcludeListTest()
    : BaseTest("make_credential_exclude_list",
               "Tests if the exclude list is used correctly.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialExcludeListTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), true);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value credential_response = std::move(absl::get<cbor::Value>(response));

  // TODO(kaczmarczyck) return instead of fail
  cbor::Value::BinaryValue cred_descriptor_id =
      test_helpers::ExtractCredentialId(credential_response);
  GetAssertionCborBuilder exclude_assertion_builder;
  exclude_assertion_builder.AddDefaultsForRequiredFields(RpId());
  response = fido2_commands::GetAssertionPositiveTest(
      device, device_tracker, exclude_assertion_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "GetAssertion on recently created credential failed.";
  }

  MakeCredentialCborBuilder exclude_list_builder;
  exclude_list_builder.AddDefaultsForRequiredFields(RpId());
  exclude_list_builder.SetResidentKeyOptions(true);
  exclude_list_builder.SetPublicKeyCredentialUserEntity(
      cbor::Value::BinaryValue(32, 0x02), "Bob");
  exclude_list_builder.SetExcludeListCredential(cred_descriptor_id);
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, exclude_list_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrCredentialExcluded,
                                   returned_status)) {
    return "MakeCredential succeeded despite known exclude list entry.";
  }

  exclude_list_builder.SetDefaultPublicKeyCredentialRpEntity(
      "another.exclude.example.com");
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, exclude_list_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "MakeCredential failed for an unrelated relying party.";
  }
  return std::nullopt;
}

MakeCredentialCredParamsTest::MakeCredentialCredParamsTest()
    : BaseTest("make_credential_cred_params",
               "Tests entries in the credential parameters list.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialCredParamsTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder cose_algorithm_builder;
  cose_algorithm_builder.AddDefaultsForRequiredFields(RpId());
  cbor::Value::ArrayValue pub_key_cred_params;
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrUnsupportedAlgorithm,
                                   returned_status)) {
    return "Accepted empty credential parameters list.";
  }

  cbor::Value::MapValue test_cred_param;
  test_cred_param[cbor::Value("alg")] = cbor::Value(-1);  // unassigned number
  test_cred_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrUnsupportedAlgorithm,
                                   returned_status)) {
    return "Accepted unsupported algorithm in credential parameters list.";
  }

  pub_key_cred_params.clear();
  test_cred_param[cbor::Value("alg")] = CborInt(Algorithm::kEs256Algorithm);
  test_cred_param[cbor::Value("type")] = cbor::Value("non-existing type");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, cose_algorithm_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrUnsupportedAlgorithm,
                                   returned_status)) {
    return "Accepted unsupported type in credential parameters list.";
  }

  pub_key_cred_params.clear();
  test_cred_param[cbor::Value("alg")] = CborInt(Algorithm::kEs256Algorithm);
  test_cred_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  test_cred_param[cbor::Value("alg")] = cbor::Value(-1);
  test_cred_param[cbor::Value("type")] = cbor::Value("non-existing type");
  pub_key_cred_params.push_back(cbor::Value(test_cred_param));
  cose_algorithm_builder.SetMapEntry(
      MakeCredentialParameters::kPubKeyCredParams,
      cbor::Value(pub_key_cred_params));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(
          device, device_tracker, cose_algorithm_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Falsely rejected cred params list with 1 good and 1 bad element.";
  }
  return std::nullopt;
}

MakeCredentialOptionRkTest::MakeCredentialOptionRkTest()
    : BaseTest(
          "make_credential_option_rk",
          "Tests if the resident key option is supported in MakeCredential.",
          {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialOptionRkTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetResidentKeyOptions(false);
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The resident key option (false) was not accepted.";
  }

  options_builder.SetResidentKeyOptions(true);
  response = fido2_commands::MakeCredentialPositiveTest(
      device, device_tracker, options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The resident key option (true) was not accepted.";
  }
  return std::nullopt;
}

MakeCredentialOptionUpFalseTest::MakeCredentialOptionUpFalseTest()
    : BaseTest(
          "make_credential_option_up_false",
          "Tests if user presence set to false is rejected in MakeCredential.",
          {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialOptionUpFalseTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserPresenceOptions(false);
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, options_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrInvalidOption,
                                   returned_status)) {
    return "Accepted option user presence set to false.";
  }
  return std::nullopt;
}

MakeCredentialOptionUvFalseTest::MakeCredentialOptionUvFalseTest()
    : BaseTest("make_credential_option_uv_false",
               "Tests if user verification set to false is accepted in "
               "MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialOptionUvFalseTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserVerificationOptions(false);
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user verification option (false) was not accepted.";
  }
  return std::nullopt;
}

MakeCredentialOptionUvTrueTest::MakeCredentialOptionUvTrueTest()
    : BaseTest("make_credential_option_uv_true",
               "Tests is user verification set to true is accepted in "
               "MakeCredential.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialOptionUvTrueTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  options_builder.SetUserVerificationOptions(true);
  options_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  options_builder.SetDefaultPinUvAuthProtocol();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The user verification option (true) was not accepted.";
  }
  return std::nullopt;
}

MakeCredentialOptionUnknownTest::MakeCredentialOptionUnknownTest()
    : BaseTest("make_credential_option_unknown",
               "Tests if unknown options are ignored in MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialOptionUnknownTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder options_builder;
  options_builder.AddDefaultsForRequiredFields(RpId());

  cbor::Value::MapValue options_map;
  options_map[cbor::Value("unknown_option")] = cbor::Value(false);
  options_builder.SetMapEntry(MakeCredentialParameters::kOptions,
                              cbor::Value(options_map));
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 options_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Falsely rejected unknown option.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthEmptyTest::MakeCredentialPinAuthEmptyTest()
    : BaseTest("make_credential_pin_auth_empty",
               "Tests the response on an empty PIN auth without a PIN in "
               "MakeCredential.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthEmptyTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();

  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrPinNotSet, returned_status)) {
    return "A zero length PIN auth param is not rejected.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthProtocolTest::MakeCredentialPinAuthProtocolTest()
    : BaseTest(
          "make_credential_pin_auth_protocol",
          "Tests if the PIN protocol parameter is checked in MakeCredential.",
          {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthProtocolTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetMapEntry(MakeCredentialParameters::kPinUvAuthProtocol,
                               cbor::Value(123456));
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinAuthInvalid,
                                   returned_status)) {
    return "Unsupported PIN protocol is not rejected.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthNoPinTest::MakeCredentialPinAuthNoPinTest()
    : BaseTest("make_credential_pin_auth_no_pin",
               "Tests if a PIN auth is rejected without a PIN set in "
               "MakeCredential.",
               {.has_pin = false}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthNoPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinNotSet, returned_status)) {
    return "PIN auth not rejected without a PIN.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthEmptyWithPinTest::MakeCredentialPinAuthEmptyWithPinTest()
    : BaseTest("make_credential_pin_auth_empty_with_pin",
               "Tests the response on an empty PIN auth with a PIN in "
               "MakeCredential.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthEmptyWithPinTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrPinInvalid, returned_status)) {
    return "A zero length PIN auth param is not rejected with a PIN set.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthTest::MakeCredentialPinAuthTest()
    : BaseTest("make_credential_pin_auth",
               "Tests if the PIN auth is correctly checked with a PIN set in "
               "MakeCredential.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder pin_auth_builder;
  pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  pin_auth_builder.SetDefaultPinUvAuthProtocol();
  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 pin_auth_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "Falsely rejected valid PIN auth.";
  }

  pin_auth_builder.SetPinUvAuthParam(cbor::Value::BinaryValue(16, 0x9a));
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinAuthInvalid,
                                   returned_status)) {
    return "Accepted wrong PIN auth.";
  }
  return std::nullopt;
}

MakeCredentialPinAuthMissingParameterTest::
    MakeCredentialPinAuthMissingParameterTest()
    : BaseTest("make_credential_pin_auth_missing_parameter",
               "Tests if client PIN fails with missing parameters in "
               "MakeCredential.",
               {.has_pin = true}, {Tag::kClientPin}) {}

std::optional<std::string> MakeCredentialPinAuthMissingParameterTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder no_pin_auth_builder;
  no_pin_auth_builder.AddDefaultsForRequiredFields(RpId());
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinRequired, returned_status)) {
    return "Missing PIN parameters were not rejected when PIN is set.";
  }

  // Error codes are guesses, the specification has a general statement only.
  no_pin_auth_builder.SetDefaultPinUvAuthProtocol();
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrPinRequired, returned_status)) {
    return "Missing PIN auth was not rejected when PIN is set.";
  }

  no_pin_auth_builder.RemoveMapEntry(
      MakeCredentialParameters::kPinUvAuthProtocol);
  no_pin_auth_builder.SetDefaultPinUvAuthParam(
      command_state->GetCurrentAuthToken());
  returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, no_pin_auth_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrMissingParameter,
                                   returned_status)) {
    return "Missing PIN protocol was not rejected when PIN is set.";
  }
  return std::nullopt;
}

MakeCredentialDuplicateTest::MakeCredentialDuplicateTest()
    : BaseTest("make_credential_duplicate",
               "Tests if two credentials have the same ID.", {.has_pin = false},
               {}) {}

std::optional<std::string> MakeCredentialDuplicateTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  absl::variant<cbor::Value, Status> response =
      command_state->MakeTestCredential(RpId(), true);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value first_response = std::move(absl::get<cbor::Value>(response));
  response = command_state->MakeTestCredential(RpId(), true);
  if (!device_tracker->CheckStatus(response)) {
    return "Cannot make credential for further tests.";
  }
  cbor::Value second_response = std::move(absl::get<cbor::Value>(response));

  cbor::Value::BinaryValue first_credential_id =
      test_helpers::ExtractCredentialId(first_response);
  cbor::Value::BinaryValue second_credential_id =
      test_helpers::ExtractCredentialId(second_response);
  if (first_credential_id == second_credential_id) {
    return "The same credential was created twice.";
  }
  return std::nullopt;
}

MakeCredentialFullStoreTest::MakeCredentialFullStoreTest()
    : BaseTest("make_credential_full_store",
               "Tests if storing lots of credentials is handled gracefully.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialFullStoreTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  constexpr int kNumCredentials = 50;
  MakeCredentialCborBuilder resident_key_builder;
  resident_key_builder.AddDefaultsForRequiredFields(RpId());
  resident_key_builder.SetResidentKeyOptions(true);
  Status returned_status = Status::kErrNone;
  int counter = 0;
  while (returned_status == Status::kErrNone && counter != kNumCredentials) {
    counter += 1;
    resident_key_builder.SetPublicKeyCredentialUserEntity(
        cbor::Value::BinaryValue(32, counter), "Greedy Greg");
    returned_status = fido2_commands::MakeCredentialNegativeTest(
        device, resident_key_builder.GetCbor(), true);
  }
  if (returned_status != Status::kErrNone) {
    if (returned_status != Status::kErrKeyStoreFull) {
      return "Filling the key store failed with an unexpected error.";
    }
  } else {
    device_tracker->AddObservation(absl::StrCat(
        "The test for full store errors was aborted after ", kNumCredentials,
        " credentials were successfully created."));
  }

  command_state->Reset();
  return std::nullopt;
}

MakeCredentialPhysicalPresenceTest::MakeCredentialPhysicalPresenceTest()
    : BaseTest("make_credential_physical_presence",
               "Tests if user touch is required for MakeCredential.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialPhysicalPresenceTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  device_tracker->IgnoreNextTouchPrompt();
  test_helpers::PrintNoTouchPrompt();

  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(RpId());
  make_credential_builder.SetResidentKeyOptions(true);
  Status returned_status = fido2_commands::MakeCredentialNegativeTest(
      device, make_credential_builder.GetCbor(), true);
  if (!device_tracker->CheckStatus(Status::kErrUserActionTimeout,
                                   returned_status)) {
    return "A credential was created without user presence.";
  }

  GetAssertionCborBuilder get_assertion_builder;
  get_assertion_builder.AddDefaultsForRequiredFields(RpId());
  returned_status = fido2_commands::GetAssertionNegativeTest(
      device, get_assertion_builder.GetCbor(), false);
  if (!device_tracker->CheckStatus(Status::kErrNoCredentials,
                                   returned_status)) {
    return "The asserted credential shouldn't exist.";
  }
  return std::nullopt;
}

MakeCredentialNonAsciiDisplayNameTest::MakeCredentialNonAsciiDisplayNameTest()
    : BaseTest("make_credential_non_ascii_display_name",
               "Tests if non-ASCII display name are accepted.",
               {.has_pin = false}, {}) {}

std::optional<std::string> MakeCredentialNonAsciiDisplayNameTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(RpId());
  make_credential_builder.SetResidentKeyOptions(true);

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

    absl::variant<cbor::Value, Status> response =
        fido2_commands::MakeCredentialPositiveTest(
            device, device_tracker, make_credential_builder.GetCbor());
    if (!device_tracker->CheckStatus(response)) {
      return "Failed on displayName with non-ASCII characters.";
    }
  }
  return std::nullopt;
}

MakeCredentialUtf8DisplayNameTest::MakeCredentialUtf8DisplayNameTest()
    : BaseTest("make_credential_utf8_display_name",
               "Tests if invalid UTF8 is caught in displayName.",
               {.has_pin = false}, {Tag::kFido2Point1}) {}

std::optional<std::string> MakeCredentialUtf8DisplayNameTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder make_credential_builder;
  make_credential_builder.AddDefaultsForRequiredFields(RpId());
  make_credential_builder.SetResidentKeyOptions(true);

  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(std::move(user_id));
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  std::string display_name = "テスト";
  pub_key_cred_user_entity[cbor::Value("displayName")] =
      cbor::Value(display_name);
  make_credential_builder.SetMapEntry(
      MakeCredentialParameters::kUser,
      cbor::Value(std::move(pub_key_cred_user_entity)));

  auto req_cbor = cbor::Writer::Write(make_credential_builder.GetCbor());
  CHECK(req_cbor.has_value()) << "encoding went wrong - TEST SUITE BUG";

  std::vector<uint8_t> display_name_bytes(display_name.begin(),
                                          display_name.end());
  auto iter = std::search(req_cbor->begin(), req_cbor->end(),
                          display_name_bytes.begin(), display_name_bytes.end());
  CHECK(iter != req_cbor->end()) << "encoding problem - TEST SUITE BUG";
  // Generating an invalid UTF-8 encoding here.
  *iter = 0x80;
  Status returned_status = fido2_commands::NonCborNegativeTest(
      device, *req_cbor, Command::kAuthenticatorMakeCredential, false);
  if (!device_tracker->CheckStatus(Status::kErrInvalidCbor, returned_status)) {
    return "UTF-8 correctness is not checked.";
  }
  return std::nullopt;
}

MakeCredentialHmacSecretTest::MakeCredentialHmacSecretTest()
    : BaseTest("make_credential_hmac_secret",
               "Tests the HMAC secret extension with MakeCredential.",
               {.has_pin = false}, {Tag::kHmacSecret}) {}

std::optional<std::string> MakeCredentialHmacSecretTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  MakeCredentialCborBuilder hmac_secret_builder;
  hmac_secret_builder.AddDefaultsForRequiredFields(RpId());
  hmac_secret_builder.SetResidentKeyOptions(true);

  cbor::Value::MapValue extension_map;
  extension_map[cbor::Value("hmac-secret")] = cbor::Value(true);
  hmac_secret_builder.SetMapEntry(MakeCredentialParameters::kExtensions,
                                  cbor::Value(extension_map));

  absl::variant<cbor::Value, Status> response =
      fido2_commands::MakeCredentialPositiveTest(device, device_tracker,
                                                 hmac_secret_builder.GetCbor());
  if (!device_tracker->CheckStatus(response)) {
    return "The command failed when using the extension.";
  }
  return std::nullopt;
}

}  // namespace fido2_tests

