// Copyright 2019-2021 Google LLC
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

#include "src/cbor_builders.h"

#include "src/constants.h"
#include "src/crypto_utility.h"

namespace fido2_tests {

CborBuilder::CborBuilder() {}

CborBuilder::~CborBuilder() {}

bool CborBuilder::HasEntry(int key) {
  return request_map_.find(cbor::Value(key)) != request_map_.end();
}

void CborBuilder::SetArbitraryMapEntry(int key, cbor::Value&& value) {
  request_map_[cbor::Value(key)] = std::move(value);
}

void CborBuilder::SetArbitraryMapEntry(cbor::Value&& key, cbor::Value&& value) {
  request_map_[std::move(key)] = std::move(value);
}

void CborBuilder::RemoveArbitraryMapEntry(int key) {
  request_map_.erase(cbor::Value(key));
}

void CborBuilder::RemoveArbitraryMapEntry(cbor::Value&& key) {
  request_map_.erase(key);
}

cbor::Value CborBuilder::GetCbor() { return cbor::Value(request_map_); }

bool MakeCredentialCborBuilder::HasEntry(MakeCredentialParameters key) {
  return CborBuilder::HasEntry(static_cast<int>(key));
}

void MakeCredentialCborBuilder::SetMapEntry(MakeCredentialParameters key,
                                            cbor::Value&& value) {
  SetArbitraryMapEntry(static_cast<int>(key), std::move(value));
}

void MakeCredentialCborBuilder::RemoveMapEntry(MakeCredentialParameters key) {
  RemoveArbitraryMapEntry(static_cast<int>(key));
}

void MakeCredentialCborBuilder::SetDefaultClientDataHash() {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetMapEntry(MakeCredentialParameters::kClientDataHash,
              cbor::Value(std::move(client_data_hash)));
}

void MakeCredentialCborBuilder::SetDefaultPublicKeyCredentialRpEntity(
    std::string rp_id) {
  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(std::move(rp_id));
  SetMapEntry(MakeCredentialParameters::kRp,
              cbor::Value(std::move(pub_key_cred_rp_entity)));
}

void MakeCredentialCborBuilder::SetDefaultPublicKeyCredentialUserEntity() {
  cbor::Value::MapValue pub_key_cred_user_entity;
  cbor::Value::BinaryValue user_id(32, 0x1D);
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(std::move(user_id));
  // TODO(kaczmarczyck) remove in final product
  // name is not required, but the Yubikey uses it, so removing it would break
  // too many tests and prevent meaningful results
  // https://github.com/fido-alliance/fido-2-specs/pull/496
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value("Adam");
  SetMapEntry(MakeCredentialParameters::kUser,
              cbor::Value(std::move(pub_key_cred_user_entity)));
}

void MakeCredentialCborBuilder::SetPublicKeyCredentialUserEntity(
    const cbor::Value::BinaryValue& user_id, std::string user_name) {
  cbor::Value::MapValue pub_key_cred_user_entity;
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] =
      cbor::Value(std::move(user_name));
  SetMapEntry(MakeCredentialParameters::kUser,
              cbor::Value(std::move(pub_key_cred_user_entity)));
}

void MakeCredentialCborBuilder::SetEs256CredentialParameters() {
  cbor::Value::ArrayValue pub_key_cred_params;
  cbor::Value::MapValue es256_param;
  es256_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kEs256Algorithm));
  es256_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(es256_param));
  SetMapEntry(MakeCredentialParameters::kPubKeyCredParams,
              cbor::Value(std::move(pub_key_cred_params)));
}

void MakeCredentialCborBuilder::SetRs256CredentialParameters() {
  cbor::Value::ArrayValue pub_key_cred_params;
  cbor::Value::MapValue rs256_param;
  rs256_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kRs256Algorithm));
  rs256_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(rs256_param));
  SetMapEntry(MakeCredentialParameters::kPubKeyCredParams,
              cbor::Value(std::move(pub_key_cred_params)));
}

void MakeCredentialCborBuilder::SetExcludeListCredential(
    const cbor::Value::BinaryValue& cred_descriptor_id) {
  cbor::Value::ArrayValue exclude_list;
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  exclude_list.push_back(cbor::Value(cred_descriptor));
  SetMapEntry(MakeCredentialParameters::kExcludeList,
              cbor::Value(std::move(exclude_list)));
}

void MakeCredentialCborBuilder::SetResidentKeyOptions(bool is_rk_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("rk")] = cbor::Value(is_rk_active);
  SetMapEntry(MakeCredentialParameters::kOptions,
              cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetUserPresenceOptions(bool is_up_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("up")] = cbor::Value(is_up_active);
  SetMapEntry(MakeCredentialParameters::kOptions,
              cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetUserVerificationOptions(bool is_uv_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("uv")] = cbor::Value(is_uv_active);
  SetMapEntry(MakeCredentialParameters::kOptions,
              cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetPinUvAuthParam(
    const cbor::Value::BinaryValue& auth_param) {
  SetMapEntry(MakeCredentialParameters::kPinUvAuthParam,
              cbor::Value(auth_param));
}

void MakeCredentialCborBuilder::SetDefaultPinUvAuthParam(
    const cbor::Value::BinaryValue& pin_token) {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetPinUvAuthParam(
      crypto_utility::LeftHmacSha256(pin_token, client_data_hash));
}

void MakeCredentialCborBuilder::SetDefaultPinUvAuthProtocol() {
  SetMapEntry(MakeCredentialParameters::kPinUvAuthProtocol, cbor::Value(1));
}

void MakeCredentialCborBuilder::AddDefaultsForRequiredFields(
    std::string rp_id) {
  if (!HasEntry(MakeCredentialParameters::kClientDataHash)) {
    SetDefaultClientDataHash();
  }
  if (!HasEntry(MakeCredentialParameters::kRp)) {
    SetDefaultPublicKeyCredentialRpEntity(std::move(rp_id));
  }
  if (!HasEntry(MakeCredentialParameters::kUser)) {
    SetDefaultPublicKeyCredentialUserEntity();
  }
  if (!HasEntry(MakeCredentialParameters::kPubKeyCredParams)) {
    SetEs256CredentialParameters();
  }
}

bool GetAssertionCborBuilder::HasEntry(GetAssertionParameters key) {
  return CborBuilder::HasEntry(static_cast<int>(key));
}

void GetAssertionCborBuilder::SetMapEntry(GetAssertionParameters key,
                                          cbor::Value&& value) {
  SetArbitraryMapEntry(static_cast<int>(key), std::move(value));
}

void GetAssertionCborBuilder::RemoveMapEntry(GetAssertionParameters key) {
  RemoveArbitraryMapEntry(static_cast<int>(key));
}

void GetAssertionCborBuilder::SetRelyingParty(std::string rp_id) {
  SetMapEntry(GetAssertionParameters::kRpId, cbor::Value(std::move(rp_id)));
}

void GetAssertionCborBuilder::SetDefaultClientDataHash() {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetMapEntry(GetAssertionParameters::kClientDataHash,
              cbor::Value(std::move(client_data_hash)));
}

void GetAssertionCborBuilder::SetAllowListCredential(
    const cbor::Value::BinaryValue& cred_descriptor_id) {
  cbor::Value::ArrayValue allow_list;
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  allow_list.push_back(cbor::Value(cred_descriptor));
  SetMapEntry(GetAssertionParameters::kAllowList,
              cbor::Value(std::move(allow_list)));
}

void GetAssertionCborBuilder::SetUserPresenceOptions(bool is_up_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("up")] = cbor::Value(is_up_active);
  SetMapEntry(GetAssertionParameters::kOptions,
              cbor::Value(std::move(authenticator_options)));
}

void GetAssertionCborBuilder::SetUserVerificationOptions(bool is_uv_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("uv")] = cbor::Value(is_uv_active);
  SetMapEntry(GetAssertionParameters::kOptions,
              cbor::Value(std::move(authenticator_options)));
}

void GetAssertionCborBuilder::SetPinUvAuthParam(
    const cbor::Value::BinaryValue& auth_param) {
  SetMapEntry(GetAssertionParameters::kPinUvAuthParam, cbor::Value(auth_param));
}

void GetAssertionCborBuilder::SetDefaultPinUvAuthParam(
    const cbor::Value::BinaryValue& pin_token) {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetPinUvAuthParam(
      crypto_utility::LeftHmacSha256(pin_token, client_data_hash));
}

void GetAssertionCborBuilder::SetDefaultPinUvAuthProtocol() {
  SetMapEntry(GetAssertionParameters::kPinUvAuthProtocol, cbor::Value(1));
}

void GetAssertionCborBuilder::AddDefaultsForRequiredFields(std::string rp_id) {
  if (!HasEntry(GetAssertionParameters::kRpId)) {
    SetRelyingParty(std::move(rp_id));
  }
  if (!HasEntry(GetAssertionParameters::kClientDataHash)) {
    SetDefaultClientDataHash();
  }
}

bool AuthenticatorClientPinCborBuilder::HasEntry(ClientPinParameters key) {
  return CborBuilder::HasEntry(static_cast<int>(key));
}

void AuthenticatorClientPinCborBuilder::SetMapEntry(ClientPinParameters key,
                                                    cbor::Value&& value) {
  SetArbitraryMapEntry(static_cast<int>(key), std::move(value));
}

void AuthenticatorClientPinCborBuilder::RemoveMapEntry(
    ClientPinParameters key) {
  RemoveArbitraryMapEntry(static_cast<int>(key));
}

void AuthenticatorClientPinCborBuilder::SetDefaultPinProtocol() {
  SetMapEntry(ClientPinParameters::kPinUvAuthProtocol, cbor::Value(1));
}

void AuthenticatorClientPinCborBuilder::SetSubCommand(
    PinSubCommand sub_command) {
  SetMapEntry(ClientPinParameters::kSubCommand,
              cbor::Value(static_cast<uint8_t>(sub_command)));
}

void AuthenticatorClientPinCborBuilder::SetKeyAgreement(
    const cbor::Value::MapValue& cose_key) {
  SetMapEntry(ClientPinParameters::kKeyAgreement, cbor::Value(cose_key));
}

void AuthenticatorClientPinCborBuilder::SetPinAuth(
    const cbor::Value::BinaryValue& pin_auth) {
  SetMapEntry(ClientPinParameters::kPinUvAuthParam, cbor::Value(pin_auth));
}

void AuthenticatorClientPinCborBuilder::SetNewPinEnc(
    const cbor::Value::BinaryValue& new_pin_enc) {
  SetMapEntry(ClientPinParameters::kNewPinEnc, cbor::Value(new_pin_enc));
}

void AuthenticatorClientPinCborBuilder::SetPinHashEnc(
    const cbor::Value::BinaryValue& pin_hash_enc) {
  SetMapEntry(ClientPinParameters::kPinHashEnc, cbor::Value(pin_hash_enc));
}

void AuthenticatorClientPinCborBuilder::SetDefaultPermissions() {
  SetMapEntry(ClientPinParameters::kPermissions, cbor::Value(0x03));
}

void AuthenticatorClientPinCborBuilder::SetPermissionsRpId(std::string rp_id) {
  SetMapEntry(ClientPinParameters::kPermissionsRpId,
              cbor::Value(std::move(rp_id)));
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetPinRetries() {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kGetPinRetries);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetKeyAgreement() {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kGetKeyAgreement);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForSetPin(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_auth,
    const cbor::Value::BinaryValue& new_pin_enc) {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kSetPin);
  }
  if (!HasEntry(ClientPinParameters::kKeyAgreement)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(ClientPinParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
  if (!HasEntry(ClientPinParameters::kNewPinEnc)) {
    SetNewPinEnc(new_pin_enc);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForChangePin(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_auth,
    const cbor::Value::BinaryValue& new_pin_enc,
    const cbor::Value::BinaryValue& pin_hash_enc) {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kChangePin);
  }
  if (!HasEntry(ClientPinParameters::kKeyAgreement)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(ClientPinParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
  if (!HasEntry(ClientPinParameters::kNewPinEnc)) {
    SetNewPinEnc(new_pin_enc);
  }
  if (!HasEntry(ClientPinParameters::kPinHashEnc)) {
    SetPinHashEnc(pin_hash_enc);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetPinToken(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_hash_enc) {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kGetPinToken);
  }
  if (!HasEntry(ClientPinParameters::kKeyAgreement)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(ClientPinParameters::kPinHashEnc)) {
    SetPinHashEnc(pin_hash_enc);
  }
}

void AuthenticatorClientPinCborBuilder::
    AddDefaultsForGetPinUvAuthTokenUsingUvWithPermissions(
        const cbor::Value::MapValue& cose_key) {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kGetPinUvAuthTokenUsingUvWithPermissions);
  }
  if (!HasEntry(ClientPinParameters::kKeyAgreement)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(ClientPinParameters::kPermissions)) {
    SetDefaultPermissions();
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetUvRetries() {
  if (!HasEntry(ClientPinParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(ClientPinParameters::kSubCommand)) {
    SetSubCommand(PinSubCommand::kGetUvRetries);
  }
}

bool CredentialManagementCborBuilder::HasEntry(
    CredentialManagementParameters key) {
  return CborBuilder::HasEntry(static_cast<int>(key));
}

void CredentialManagementCborBuilder::SetMapEntry(
    CredentialManagementParameters key, cbor::Value&& value) {
  SetArbitraryMapEntry(static_cast<int>(key), std::move(value));
}

void CredentialManagementCborBuilder::RemoveMapEntry(
    CredentialManagementParameters key) {
  RemoveArbitraryMapEntry(static_cast<int>(key));
}

void CredentialManagementCborBuilder::SetSubCommand(
    ManagementSubCommand sub_command) {
  SetMapEntry(CredentialManagementParameters::kSubCommand,
              CborInt(sub_command));
}

void CredentialManagementCborBuilder::SetSubCommandParamsRpIdHash(
    const cbor::Value::BinaryValue& rp_id_hash) {
  cbor::Value::MapValue sub_command_params;
  sub_command_params[CborInt(ManagementSubCommandParams::kRpIdHash)] =
      cbor::Value(rp_id_hash);
  SetMapEntry(CredentialManagementParameters::kSubCommandParams,
              cbor::Value(std::move(sub_command_params)));
}

void CredentialManagementCborBuilder::SetSubCommandParamsCredentialId(
    const cbor::Value::BinaryValue& cred_descriptor_id) {
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  cbor::Value::MapValue sub_command_params;
  sub_command_params[CborInt(ManagementSubCommandParams::kCredentialId)] =
      cbor::Value(std::move(cred_descriptor));
  SetMapEntry(CredentialManagementParameters::kSubCommandParams,
              cbor::Value(std::move(sub_command_params)));
}

void CredentialManagementCborBuilder::SetSubCommandParamsCredentialAndUser(
    const cbor::Value::BinaryValue& cred_descriptor_id,
    const cbor::Value::BinaryValue& user_id, std::string user_name) {
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  cbor::Value::MapValue user;
  user[cbor::Value("id")] = cbor::Value(user_id);
  user[cbor::Value("name")] = cbor::Value(std::move(user_name));
  cbor::Value::MapValue sub_command_params;
  sub_command_params[CborInt(ManagementSubCommandParams::kCredentialId)] =
      cbor::Value(std::move(cred_descriptor));
  sub_command_params[CborInt(ManagementSubCommandParams::kUser)] =
      cbor::Value(std::move(user));
  SetMapEntry(CredentialManagementParameters::kSubCommandParams,
              cbor::Value(std::move(sub_command_params)));
}

void CredentialManagementCborBuilder::SetDefaultPinProtocol() {
  SetMapEntry(CredentialManagementParameters::kPinUvAuthProtocol,
              cbor::Value(1));
}

void CredentialManagementCborBuilder::SetPinAuth(
    const cbor::Value::BinaryValue& pin_auth) {
  SetMapEntry(CredentialManagementParameters::kPinUvAuthParam,
              cbor::Value(pin_auth));
}

void CredentialManagementCborBuilder::AddDefaultsForGetCredsMetadata(
    const cbor::Value::BinaryValue& pin_auth) {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kGetCredsMetadata);
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
}

void CredentialManagementCborBuilder::AddDefaultsForEnumerateRpsBegin(
    const cbor::Value::BinaryValue& pin_auth) {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kEnumerateRpsBegin);
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
}

void CredentialManagementCborBuilder::AddDefaultsForEnumerateRpsGetNextRp() {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kEnumerateRpsGetNextRp);
  }
}

void CredentialManagementCborBuilder::AddDefaultsForEnumerateCredentialsBegin(
    const cbor::Value::BinaryValue& rp_id_hash,
    const cbor::Value::BinaryValue& pin_auth) {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kEnumerateCredentialsBegin);
  }
  if (!HasEntry(CredentialManagementParameters::kSubCommandParams)) {
    SetSubCommandParamsRpIdHash(rp_id_hash);
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
}

void CredentialManagementCborBuilder::
    AddDefaultsForEnumerateCredentialsGetNextCredential() {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kEnumerateCredentialsGetNextCredential);
  }
}

void CredentialManagementCborBuilder::AddDefaultsForDeleteCredential(
    const cbor::Value::BinaryValue& cred_descriptor_id,
    const cbor::Value::BinaryValue& pin_auth) {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kDeleteCredential);
  }
  if (!HasEntry(CredentialManagementParameters::kSubCommandParams)) {
    SetSubCommandParamsCredentialId(cred_descriptor_id);
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
}

void CredentialManagementCborBuilder::AddDefaultsForUpdateUserInformation(
    const cbor::Value::BinaryValue& cred_descriptor_id,
    const cbor::Value::BinaryValue& user_id, std::string user_name,
    const cbor::Value::BinaryValue& pin_auth) {
  if (!HasEntry(CredentialManagementParameters::kSubCommand)) {
    SetSubCommand(ManagementSubCommand::kDeleteCredential);
  }
  if (!HasEntry(CredentialManagementParameters::kSubCommandParams)) {
    SetSubCommandParamsCredentialAndUser(cred_descriptor_id, user_id,
                                         std::move(user_name));
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthProtocol)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(CredentialManagementParameters::kPinUvAuthParam)) {
    SetPinAuth(pin_auth);
  }
}

}  // namespace fido2_tests

