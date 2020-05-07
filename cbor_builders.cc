// Copyright 2019 Google LLC
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

#include "cbor_builders.h"

#include "constants.h"
#include "crypto_utility.h"

namespace fido2_tests {

CborBuilder::CborBuilder() {}

CborBuilder::~CborBuilder() {}

bool CborBuilder::HasEntry(int key) {
  return request_map_.find(cbor::Value(key)) != request_map_.end();
}

void CborBuilder::SetMapEntry(int key, cbor::Value&& value) {
  request_map_[cbor::Value(key)] = std::move(value);
}

void CborBuilder::SetMapEntry(cbor::Value&& key, cbor::Value&& value) {
  request_map_[std::move(key)] = std::move(value);
}

void CborBuilder::RemoveMapEntry(int key) {
  request_map_.erase(cbor::Value(key));
}

void CborBuilder::RemoveMapEntry(cbor::Value&& key) { request_map_.erase(key); }

cbor::Value CborBuilder::GetCbor() { return cbor::Value(request_map_); }

void MakeCredentialCborBuilder::SetDefaultClientDataHash() {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetMapEntry(1, cbor::Value(std::move(client_data_hash)));
}

void MakeCredentialCborBuilder::SetDefaultPublicKeyCredentialRpEntity(
    const std::string& rp_id) {
  cbor::Value::MapValue pub_key_cred_rp_entity;
  pub_key_cred_rp_entity[cbor::Value("id")] = cbor::Value(rp_id);
  SetMapEntry(2, cbor::Value(std::move(pub_key_cred_rp_entity)));
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
  SetMapEntry(3, cbor::Value(std::move(pub_key_cred_user_entity)));
}

void MakeCredentialCborBuilder::SetPublicKeyCredentialUserEntity(
    const cbor::Value::BinaryValue& user_id, const std::string& user_name) {
  cbor::Value::MapValue pub_key_cred_user_entity;
  pub_key_cred_user_entity[cbor::Value("id")] = cbor::Value(user_id);
  pub_key_cred_user_entity[cbor::Value("name")] = cbor::Value(user_name);
  SetMapEntry(3, cbor::Value(std::move(pub_key_cred_user_entity)));
}

void MakeCredentialCborBuilder::SetEs256CredentialParameters() {
  cbor::Value::ArrayValue pub_key_cred_params;
  cbor::Value::MapValue es256_param;
  es256_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kEs256Algorithm));
  es256_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(es256_param));
  SetMapEntry(4, cbor::Value(std::move(pub_key_cred_params)));
}

void MakeCredentialCborBuilder::SetRs256CredentialParameters() {
  cbor::Value::ArrayValue pub_key_cred_params;
  cbor::Value::MapValue rs256_param;
  rs256_param[cbor::Value("alg")] =
      cbor::Value(static_cast<int>(Algorithm::kRs256Algorithm));
  rs256_param[cbor::Value("type")] = cbor::Value("public-key");
  pub_key_cred_params.push_back(cbor::Value(rs256_param));
  SetMapEntry(4, cbor::Value(std::move(pub_key_cred_params)));
}

void MakeCredentialCborBuilder::SetExcludeListCredential(
    const cbor::Value::BinaryValue& cred_descriptor_id) {
  cbor::Value::ArrayValue exclude_list;
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  exclude_list.push_back(cbor::Value(cred_descriptor));
  SetMapEntry(5, cbor::Value(std::move(exclude_list)));
}

void MakeCredentialCborBuilder::SetResidentialKeyOptions(bool is_rk_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("rk")] = cbor::Value(is_rk_active);
  SetMapEntry(7, cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetUserPresenceOptions(bool is_up_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("up")] = cbor::Value(is_up_active);
  SetMapEntry(7, cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetUserVerificationOptions(bool is_uv_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("uv")] = cbor::Value(is_uv_active);
  SetMapEntry(7, cbor::Value(std::move(authenticator_options)));
}

void MakeCredentialCborBuilder::SetPinUvAuthParam(
    const cbor::Value::BinaryValue& auth_param) {
  SetMapEntry(8, cbor::Value(auth_param));
}

void MakeCredentialCborBuilder::SetDefaultPinUvAuthParam(
    const cbor::Value::BinaryValue& pin_token) {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetPinUvAuthParam(
      crypto_utility::LeftHmacSha256(pin_token, client_data_hash));
}

void MakeCredentialCborBuilder::SetDefaultPinUvAuthProtocol() {
  SetMapEntry(9, cbor::Value(1));
}

void MakeCredentialCborBuilder::AddDefaultsForRequiredFields(
    const std::string& rp_id) {
  if (!HasEntry(1)) {
    SetDefaultClientDataHash();
  }
  if (!HasEntry(2)) {
    SetDefaultPublicKeyCredentialRpEntity(rp_id);
  }
  if (!HasEntry(3)) {
    SetDefaultPublicKeyCredentialUserEntity();
  }
  if (!HasEntry(4)) {
    SetEs256CredentialParameters();
  }
}

void GetAssertionCborBuilder::SetRelyingParty(const std::string& rp_id) {
  SetMapEntry(1, cbor::Value(rp_id));
}

void GetAssertionCborBuilder::SetDefaultClientDataHash() {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetMapEntry(2, cbor::Value(std::move(client_data_hash)));
}

void GetAssertionCborBuilder::SetAllowListCredential(
    const cbor::Value::BinaryValue& cred_descriptor_id) {
  cbor::Value::ArrayValue allow_list;
  cbor::Value::MapValue cred_descriptor;
  cred_descriptor[cbor::Value("type")] = cbor::Value("public-key");
  cred_descriptor[cbor::Value("id")] = cbor::Value(cred_descriptor_id);
  allow_list.push_back(cbor::Value(cred_descriptor));
  SetMapEntry(3, cbor::Value(std::move(allow_list)));
}

void GetAssertionCborBuilder::SetUserPresenceOptions(bool is_up_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("up")] = cbor::Value(is_up_active);
  SetMapEntry(5, cbor::Value(std::move(authenticator_options)));
}

void GetAssertionCborBuilder::SetUserVerificationOptions(bool is_uv_active) {
  cbor::Value::MapValue authenticator_options;
  authenticator_options[cbor::Value("uv")] = cbor::Value(is_uv_active);
  SetMapEntry(5, cbor::Value(std::move(authenticator_options)));
}

void GetAssertionCborBuilder::SetPinUvAuthParam(
    const cbor::Value::BinaryValue& auth_param) {
  SetMapEntry(6, cbor::Value(auth_param));
}

void GetAssertionCborBuilder::SetDefaultPinUvAuthParam(
    const cbor::Value::BinaryValue& pin_token) {
  cbor::Value::BinaryValue client_data_hash(32, 0xcd);
  SetPinUvAuthParam(
      crypto_utility::LeftHmacSha256(pin_token, client_data_hash));
}

void GetAssertionCborBuilder::SetDefaultPinUvAuthProtocol() {
  SetMapEntry(7, cbor::Value(1));
}

void GetAssertionCborBuilder::AddDefaultsForRequiredFields(std::string rp_id) {
  if (!HasEntry(1)) {
    SetRelyingParty(rp_id);
  }
  if (!HasEntry(2)) {
    SetDefaultClientDataHash();
  }
}

void AuthenticatorClientPinCborBuilder::SetDefaultPinProtocol() {
  SetMapEntry(1, cbor::Value(1));
}

void AuthenticatorClientPinCborBuilder::SetSubCommand(
    PinSubCommand sub_command) {
  SetMapEntry(2, cbor::Value(static_cast<uint8_t>(sub_command)));
}

void AuthenticatorClientPinCborBuilder::SetKeyAgreement(
    const cbor::Value::MapValue& cose_key) {
  SetMapEntry(3, cbor::Value(cose_key));
}

void AuthenticatorClientPinCborBuilder::SetPinAuth(
    const cbor::Value::BinaryValue& pin_auth) {
  SetMapEntry(4, cbor::Value(pin_auth));
}

void AuthenticatorClientPinCborBuilder::SetNewPinEnc(
    const cbor::Value::BinaryValue& new_pin_enc) {
  SetMapEntry(5, cbor::Value(new_pin_enc));
}

void AuthenticatorClientPinCborBuilder::SetPinHashEnc(
    const cbor::Value::BinaryValue& pin_hash_enc) {
  SetMapEntry(6, cbor::Value(pin_hash_enc));
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetPinRetries() {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kGetPinRetries);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetKeyAgreement() {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kGetKeyAgreement);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForSetPin(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_auth,
    const cbor::Value::BinaryValue& new_pin_enc) {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kSetPin);
  }
  if (!HasEntry(3)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(4)) {
    SetPinAuth(pin_auth);
  }
  if (!HasEntry(5)) {
    SetNewPinEnc(new_pin_enc);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForChangePin(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_auth,
    const cbor::Value::BinaryValue& new_pin_enc,
    const cbor::Value::BinaryValue& pin_hash_enc) {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kChangePin);
  }
  if (!HasEntry(3)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(4)) {
    SetPinAuth(pin_auth);
  }
  if (!HasEntry(5)) {
    SetNewPinEnc(new_pin_enc);
  }
  if (!HasEntry(6)) {
    SetPinHashEnc(pin_hash_enc);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetPinUvAuthTokenUsingPin(
    const cbor::Value::MapValue& cose_key,
    const cbor::Value::BinaryValue& pin_hash_enc) {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kGetPinToken);
  }
  if (!HasEntry(3)) {
    SetKeyAgreement(cose_key);
  }
  if (!HasEntry(6)) {
    SetPinHashEnc(pin_hash_enc);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetPinUvAuthTokenUsingUv(
    const cbor::Value::MapValue& cose_key) {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kGetPinToken);
  }
  if (!HasEntry(3)) {
    SetKeyAgreement(cose_key);
  }
}

void AuthenticatorClientPinCborBuilder::AddDefaultsForGetUvRetries() {
  if (!HasEntry(1)) {
    SetDefaultPinProtocol();
  }
  if (!HasEntry(2)) {
    SetSubCommand(PinSubCommand::kGetUvRetries);
  }
}

}  // namespace fido2_tests
