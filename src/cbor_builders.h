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

#ifndef CBOR_BUILDERS_H_
#define CBOR_BUILDERS_H_

#include "src/constants.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// This is the base class for all of the following builder classes. Usage of
// this class is possible, but discouraged. The specialized classes for each
// command offer helper functions for constructing correct requests.
class CborBuilder {
 public:
  CborBuilder();
  ~CborBuilder();
  // Sets or overwrites the given key. Please prefer the more specific
  // SetMapEntry functions when possible.
  void SetArbitraryMapEntry(int key, cbor::Value&& value);
  // Sets or overwrites the given key. This should only be used for the
  // construction of deliberately abnormal or invalid CBOR structures.
  void SetArbitraryMapEntry(cbor::Value&& key, cbor::Value&& value);
  // Removes the map entry at given key, if existing. Please prefer the more
  // specific RemoveMapEntry functions when possible.
  void RemoveArbitraryMapEntry(int key);
  // Removes the map entry at given key, if existing. Also works for
  // deliberately abnormal or invalid CBOR structures.
  void RemoveArbitraryMapEntry(cbor::Value&& key);
  // Return a CBOR Value representation of the current internal state.
  cbor::Value GetCbor();

 protected:
  // Checks if the key is already set for the current request.
  bool HasEntry(int key);

 private:
  cbor::Value::MapValue request_map_;
};

// Following the builder pattern, this class has setters to change its internal
// state. At any point (even more than once), you can call GetCbor for a
// Value object that can be sent to the authenticator. The SetMapEntry function
// is the most general, while all other functions set specific keys of the
// internal map.
// Example:
//    MakeCredentialCborBuilder builder;
//    builder.AddDefaultsForRequiredFields(rp_id);
//    cbor::Value request_cbor = builder.GetCbor();
class MakeCredentialCborBuilder : public CborBuilder {
 public:
  // Checks if the entry is present for the given key.
  bool HasEntry(MakeCredentialParameters key);
  // Sets or overwrites the given key.
  void SetMapEntry(MakeCredentialParameters key, cbor::Value&& value);
  // Removes the map entry at given key, if existing.
  void RemoveMapEntry(MakeCredentialParameters key);
  // Sets or overwrites key 1 with a cbor::Value::BinaryValue.
  void SetDefaultClientDataHash();
  // Sets or overwrites key 2 with the cbor::Value::MapValue
  // {"id": relying party ID}.
  void SetDefaultPublicKeyCredentialRpEntity(std::string rp_id);
  // Sets or overwrites key 3 with a cbor::Value::MapValue mapping "id" and
  // "name" to default values.
  void SetDefaultPublicKeyCredentialUserEntity();
  // Sets or overwrites key 3 with a cbor::Value::MapValue mapping "id" and
  // "name" to the parameters.
  void SetPublicKeyCredentialUserEntity(const cbor::Value::BinaryValue& user_id,
                                        std::string user_name);
  // Sets or overwrites key 4 with a cbor::Value::MapValue enabling ES256.
  void SetEs256CredentialParameters();
  // Sets or overwrites key 4 with a cbor::Value::MapValue enabling RS256.
  void SetRs256CredentialParameters();
  // Sets or overwrites key 5 with a cbor::Value::ArrayValue including one
  // credential descriptor as an exclude list.
  void SetExcludeListCredential(
      const cbor::Value::BinaryValue& cred_descriptor_id);
  // Sets or overwrites key 7 with a cbor::Value::MapValue to require
  // resident keys.
  void SetResidentKeyOptions(bool is_rk_active);
  // Sets or overwrites key 7 with a cbor::Value::MapValue to require user
  // presence.
  void SetUserPresenceOptions(bool is_up_active);
  // Sets or overwrites key 7 with a cbor::Value::MapValue to require user
  // verification.
  void SetUserVerificationOptions(bool is_uv_active);
  // Sets or overwrites key 8 with the given cbor::Value::BinaryValue.
  void SetPinUvAuthParam(const cbor::Value::BinaryValue& auth_param);
  // Sets or overwrites key 8 with a cbor::Value::BinaryValue generated using
  // the passed pin_token and a default value for the clientDataHash.
  void SetDefaultPinUvAuthParam(const cbor::Value::BinaryValue& pin_token);
  // Sets or overwrites key 9 with a default PIN protocol.
  void SetDefaultPinUvAuthProtocol();
  // Sets defaults for keys 1 to 4 ONLY if they are not present yet.
  void AddDefaultsForRequiredFields(std::string rp_id);
};

// See MakeCredentialCborBuilder, this is a similar class for GetAssertion.
class GetAssertionCborBuilder : public CborBuilder {
 public:
  // Checks if the entry is present for the given key.
  bool HasEntry(GetAssertionParameters key);
  // Sets or overwrites the given key.
  void SetMapEntry(GetAssertionParameters key, cbor::Value&& value);
  // Removes the map entry at given key, if existing.
  void RemoveMapEntry(GetAssertionParameters key);
  // Sets or overwrites key 1 with the cbor::Value::String rp_id.
  void SetRelyingParty(std::string rp_id);
  // Sets or overwrites key 2 with a cbor::Value::BinaryValue.
  void SetDefaultClientDataHash();
  // Sets or overwrites key 3 with a cbor::Value::ArrayValue including one
  // credential descriptor as an allow list.
  void SetAllowListCredential(
      const cbor::Value::BinaryValue& cred_descriptor_id);
  // Sets or overwrites key 5 with a cbor::Value::MapValue to require user
  // presence.
  void SetUserPresenceOptions(bool is_up_active);
  // Sets or overwrites key 5 with a cbor::Value::MapValue to require user
  // verification.
  void SetUserVerificationOptions(bool is_uv_active);
  // Sets or overwrites key 6 with the given cbor::Value::BinaryValue.
  void SetPinUvAuthParam(const cbor::Value::BinaryValue& auth_param);
  // Sets or overwrites key 6 with a cbor::Value::BinaryValue generated using
  // the passed pin_token and a default value for the clientDataHash.
  void SetDefaultPinUvAuthParam(const cbor::Value::BinaryValue& pin_token);
  // Sets or overwrites key 7 with a default PIN protocol.
  void SetDefaultPinUvAuthProtocol();
  // Sets defaults for keys 1 and 2 ONLY if they are not present yet.
  void AddDefaultsForRequiredFields(std::string rp_id);
};

// See MakeCredentialCborBuilder, this is a similar class for
// AuthenticatorClientPin.
class AuthenticatorClientPinCborBuilder : public CborBuilder {
 public:
  // Checks if the entry is present for the given key.
  bool HasEntry(ClientPinParameters key);
  // Sets or overwrites the given key.
  void SetMapEntry(ClientPinParameters key, cbor::Value&& value);
  // Removes the map entry at given key, if existing.
  void RemoveMapEntry(ClientPinParameters key);
  // Sets or overwrites key 1 with the unsigned value 1.
  void SetDefaultPinProtocol();
  // Sets or overwrites key 2 with the given integer.
  void SetSubCommand(PinSubCommand sub_command);
  // Sets or overwrites key 3 with the given bytestring representing a COSE
  // public key.
  void SetKeyAgreement(const cbor::Value::MapValue& cose_key);
  // Sets or overwrites key 4 with the given bytestring.
  void SetPinAuth(const cbor::Value::BinaryValue& pin_auth);
  // Sets or overwrites key 5 with the given bytestring.
  void SetNewPinEnc(const cbor::Value::BinaryValue& new_pin_enc);
  // Sets or overwrites key 6 with the given bytestring.
  void SetPinHashEnc(const cbor::Value::BinaryValue& pin_hash_enc);
  // Sets or overwrites key 9 with the unsigned value 0x03.
  void SetDefaultPermissions();
  // Sets or overwrites key 10 with the given string.
  void SetPermissionsRpId(std::string rp_id);
  // Sets defaults for keys 1 and 2 ONLY if they are not present yet.
  void AddDefaultsForGetPinRetries();
  // Sets defaults for keys 1 and 2 ONLY if they are not present yet.
  void AddDefaultsForGetKeyAgreement();
  // Sets defaults for keys 1 to 5 ONLY if they are not present yet.
  void AddDefaultsForSetPin(const cbor::Value::MapValue& cose_key,
                            const cbor::Value::BinaryValue& pin_auth,
                            const cbor::Value::BinaryValue& new_pin_enc);
  // Sets defaults for keys 1 to 6 ONLY if they are not present yet.
  void AddDefaultsForChangePin(const cbor::Value::MapValue& cose_key,
                               const cbor::Value::BinaryValue& pin_auth,
                               const cbor::Value::BinaryValue& new_pin_enc,
                               const cbor::Value::BinaryValue& pin_hash_enc);
  // Sets defaults for keys 1, 2, 3 and 6 ONLY if they are not present yet.
  void AddDefaultsForGetPinToken(const cbor::Value::MapValue& cose_key,
                                 const cbor::Value::BinaryValue& pin_hash_enc);
  // Sets defaults for keys 1, 2, 3, 9 and 10 ONLY if they are not present yet.
  void AddDefaultsForGetPinUvAuthTokenUsingUvWithPermissions(
      const cbor::Value::MapValue& cose_key);
  // Sets defaults for keys 1 and 2 ONLY if they are not present yet.
  void AddDefaultsForGetUvRetries();
};

// See MakeCredentialCborBuilder, this is a similar class for
// AuthenticatorCredentialManagement.
class CredentialManagementCborBuilder : public CborBuilder {
 public:
  // Checks if the entry is present for the given key.
  bool HasEntry(CredentialManagementParameters key);
  // Sets or overwrites the given key.
  void SetMapEntry(CredentialManagementParameters key, cbor::Value&& value);
  // Removes the map entry at given key, if existing.
  void RemoveMapEntry(CredentialManagementParameters key);
  // Sets or overwrites key 1 with the given integer.
  void SetSubCommand(ManagementSubCommand sub_command);
  // Sets or overwrites key 2 with a map containing the given RP ID hash.
  void SetSubCommandParamsRpIdHash(const cbor::Value::BinaryValue& rp_id_hash);
  // Sets or overwrites key 2 with a map containing a credential descriptor with
  // the given credential ID.
  void SetSubCommandParamsCredentialId(
      const cbor::Value::BinaryValue& cred_descriptor_id);
  // Sets or overwrites key 2 with a map containing a credential descriptor with
  // the given credential ID and a user entity with given ID and name.
  void SetSubCommandParamsCredentialAndUser(
      const cbor::Value::BinaryValue& cred_descriptor_id,
      const cbor::Value::BinaryValue& user_id, std::string user_name);
  // Sets or overwrites key 3 with the unsigned value 1.
  void SetDefaultPinProtocol();
  // Sets or overwrites key 4 with the given bytestring.
  void SetPinAuth(const cbor::Value::BinaryValue& pin_auth);
  // Sets defaults for keys 1, 2 and 4 ONLY if they are not present yet.
  void AddDefaultsForGetCredsMetadata(const cbor::Value::BinaryValue& pin_auth);
  void AddDefaultsForEnumerateRpsBegin(
      const cbor::Value::BinaryValue& pin_auth);
  void AddDefaultsForEnumerateRpsGetNextRp();
  void AddDefaultsForEnumerateCredentialsBegin(
      const cbor::Value::BinaryValue& rp_id_hash,
      const cbor::Value::BinaryValue& pin_auth);
  void AddDefaultsForEnumerateCredentialsGetNextCredential();
  void AddDefaultsForDeleteCredential(
      const cbor::Value::BinaryValue& cred_descriptor_id,
      const cbor::Value::BinaryValue& pin_auth);
  void AddDefaultsForUpdateUserInformation(
      const cbor::Value::BinaryValue& cred_descriptor_id,
      const cbor::Value::BinaryValue& user_id, std::string user_name,
      const cbor::Value::BinaryValue& pin_auth);
};

}  // namespace fido2_tests

#endif  // CBOR_BUILDERS_H_

