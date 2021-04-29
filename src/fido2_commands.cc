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

#include "src/fido2_commands.h"

#include <cstdint>
#include <iostream>

#include "absl/container/flat_hash_set.h"
#include "absl/types/optional.h"
#include "glog/logging.h"
#include "src/constants.h"
#include "src/crypto_utility.h"
#include "src/parameter_check.h"
#include "third_party/chromium_components_cbor/reader.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {
namespace fido2_commands {

using ByteVector = std::vector<uint8_t>;

namespace {
void CheckExtensions(const ByteVector& extension_data) {
  if (extension_data.empty()) {
    return;
  }
  absl::optional<cbor::Value> extensions = cbor::Reader::Read(extension_data);
  CHECK(extensions.has_value()) << "CBOR decoding of extensions failed";
  CHECK(extensions->is_map()) << "extensions response is not a map";
}

bool IsKeyInRequest(const cbor::Value& request, int map_key) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  return request_map.find(cbor::Value(map_key)) != request_map.end();
}

size_t PubKeyDuplicateCheck(KeyChecker* key_checker,
                            const ByteVector& pub_key_cose) {
  size_t num_bytes_consumed;
  absl::optional<cbor::Value> decoded_pub_key =
      cbor::Reader::Read(pub_key_cose, &num_bytes_consumed);
  CHECK(decoded_pub_key.has_value()) << "CBOR decoding of public key failed";
  CHECK(decoded_pub_key->is_map()) << "CBOR response is not a map";
  const auto& pub_key_map = decoded_pub_key->GetMap();

  auto iter = pub_key_map.find(cbor::Value(3));
  CHECK(iter != pub_key_map.end())
      << "no attStmt (key 3) in MakeCredential response";
  CHECK(iter->second.is_integer()) << "alg in public key map is not an integer";
  int64_t alg = iter->second.GetInteger();

  switch (alg) {
    case static_cast<int>(Algorithm::kEs256Algorithm): {
      iter = pub_key_map.find(cbor::Value(-2));
      CHECK(iter != pub_key_map.end()) << "key -2 not found in public key map";
      CHECK(iter->second.is_bytestring())
          << "x coordinate entry is not a bytestring";
      ByteVector x = iter->second.GetBytestring();
      iter = pub_key_map.find(cbor::Value(-3));
      CHECK(iter != pub_key_map.end()) << "key -3 not found in public key map";
      CHECK(iter->second.is_bytestring())
          << "y coordinate entry is not a bytestring";
      ByteVector y = iter->second.GetBytestring();
      ByteVector concat;
      concat.reserve(x.size() + y.size());
      concat.insert(concat.end(), x.begin(), x.end());
      concat.insert(concat.end(), y.begin(), y.end());
      key_checker->CheckKey(concat);
      break;
    }
    case static_cast<int>(Algorithm::kRs256Algorithm): {
      iter = pub_key_map.find(cbor::Value(-1));
      CHECK(iter != pub_key_map.end()) << "key -1 not found in public key map";
      CHECK(iter->second.is_bytestring())
          << "the public key is not a bytestring";
      ByteVector n = iter->second.GetBytestring();
      key_checker->CheckKey(n);
      break;
    }
    default: {
      // TODO(kaczmarczyck) update for more possible algorithms and parameters
      CHECK(false) << "alg " << alg
                   << " in public key map did not match anything implemented";
    }
  }
  return num_bytes_consumed;
}

std::string ExtractRpIdFromMakeCredentialRequest(const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(CborInt(MakeCredentialParameters::kRp));
  CHECK(req_iter != request_map.end()) << "RP not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_map()) << "RP is not a map - TEST SUITE BUG";
  const auto& inner_map = req_iter->second.GetMap();
  auto rp_entity_iter = inner_map.find(cbor::Value("id"));
  CHECK(rp_entity_iter != inner_map.end())
      << "\"id\" not in relying party identity map - TEST SUITE BUG";
  CHECK(rp_entity_iter->second.is_string())
      << "\"id\" is not a string - TEST SUITE BUG";
  return rp_entity_iter->second.GetString();
}

std::string ExtractRpIdFromGetAssertionRequest(const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(CborInt(GetAssertionParameters::kRpId));
  CHECK(req_iter != request_map.end())
      << "RP ID not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_string())
      << "RP ID is not a string - TEST SUITE BUG";
  return req_iter->second.GetString();
}

PinSubCommand ExtractPinSubCommand(const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(CborInt(ClientPinParameters::kSubCommand));
  CHECK(req_iter != request_map.end())
      << "subcommand not in request - TEST SUITE BUG";
  return static_cast<PinSubCommand>(req_iter->second.GetUnsigned());
}

ManagementSubCommand ExtractManagementSubCommand(const cbor::Value& request) {
  const auto& request_map = request.GetMap();
  auto req_iter =
      request_map.find(CborInt(CredentialManagementParameters::kSubCommand));
  CHECK(req_iter != request_map.end())
      << "sub command not in request - TEST SUITE BUG";
  return static_cast<ManagementSubCommand>(req_iter->second.GetUnsigned());
}

cbor::Value::BinaryValue ExtractUniqueCredentialFromAllowList(
    const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(CborInt(GetAssertionParameters::kAllowList));
  CHECK(req_iter != request_map.end())
      << "allow list not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_array())
      << "allow list is not an array - TEST SUITE BUG";
  CHECK_EQ(req_iter->second.GetArray().size(), 1u)
      << "allow list length is not 1";
  const auto& cred_descriptor_entry = req_iter->second.GetArray()[0];
  CHECK(cred_descriptor_entry.is_map())
      << "credential descriptor is not a map - TEST SUITE BUG";
  const auto& cred_descriptor = cred_descriptor_entry.GetMap();
  auto desc_iter = cred_descriptor.find(cbor::Value("id"));
  CHECK(desc_iter != cred_descriptor.end())
      << "id not in credential descriptor - TEST SUITE BUG";
  CHECK(desc_iter->second.is_bytestring())
      << "credential ID is not a bytestring - TEST SUITE BUG";
  return desc_iter->second.GetBytestring();
}

// Default is true.
bool ExtractUpOptionFromGetAssertionRequest(const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(CborInt(GetAssertionParameters::kOptions));
  if (req_iter == request_map.end()) {
    return true;
  }
  CHECK(req_iter->second.is_map()) << "options are not a map - TEST SUITE BUG";
  const auto& inner_map = req_iter->second.GetMap();
  auto options_iter = inner_map.find(cbor::Value("up"));
  if (options_iter == inner_map.end()) {
    return true;
  }
  CHECK(options_iter->second.is_bool())
      << "option \"up\" is not a boolean - TEST SUITE BUG";
  return options_iter->second.GetBool();
}

// Logs an observation and returns a Status, if the condition is not met.
// Requires a device_tracker object to exist.
#define TRUE_OR_RETURN(condition, s)       \
  do {                                     \
    if (!(condition)) {                    \
      device_tracker->AddObservation((s)); \
      return Status::kErrTestToolInternal; \
    }                                      \
  } while (0)
}  // namespace

absl::variant<cbor::Value, Status> MakeCredentialPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request) {
  auto encoded_request = cbor::Writer::Write(request);
  CHECK(encoded_request.has_value()) << "encoding went wrong - TEST SUITE BUG";

  ByteVector response_cbor;
  Status status = device->ExchangeCbor(Command::kAuthenticatorMakeCredential,
                                       *encoded_request, true, &response_cbor);
  if (status != Status::kErrNone) {
    return status;
  }

  absl::optional<cbor::Value> decoded_response =
      cbor::Reader::Read(response_cbor);
  CHECK(decoded_response.has_value()) << "CBOR decoding failed";
  CHECK(decoded_response->is_map()) << "CBOR response is not a map";
  const auto& decoded_map = decoded_response->GetMap();

  auto map_iter = decoded_map.find(CborInt(MakeCredentialResponse::kFmt));
  CHECK(map_iter != decoded_map.end())
      << "no fmt (key 1) in MakeCredential response";
  CHECK(map_iter->second.is_string()) << "fmt is not a string";
  std::string fmt = map_iter->second.GetString();

  map_iter = decoded_map.find(CborInt(MakeCredentialResponse::kAuthData));
  CHECK(map_iter != decoded_map.end())
      << "no authData (key 2) in MakeCredential response";
  CHECK(map_iter->second.is_bytestring())
      << "authData entry is not a bytestring";
  cbor::Value::BinaryValue auth_data = map_iter->second.GetBytestring();
  CHECK_GE(auth_data.size(), 32u)
      << "authData is too small to fit the relying party ID hash";
  ByteVector expected_rp_id_hash =
      crypto_utility::Sha256Hash(ExtractRpIdFromMakeCredentialRequest(request));
  CHECK_EQ(expected_rp_id_hash.size(), 32u)
      << "relying party ID hash is not 32 byte";
  CHECK(std::equal(expected_rp_id_hash.begin(), expected_rp_id_hash.end(),
                   auth_data.begin()))
      << "unexpected relying party ID hash";

  CHECK_GE(auth_data.size(), 33u) << "authData does not fit the flags";
  uint8_t flags = auth_data[32];
  // MakeCredential always checks user presence, regardless of verification.
  CHECK(flags & 0x01) << "user presence flag was not set";
  if (IsKeyInRequest(request, static_cast<int>(
                                  MakeCredentialParameters::kPinUvAuthParam))) {
    CHECK(flags & 0x04) << "no user verification flag despite auth token";
  }

  CHECK_GE(auth_data.size(), 37u) << "authData does not fit the counter";
  uint32_t signature_counter = absl::big_endian::Load32(auth_data.data() + 33);

  CHECK(flags & 0x40) << "attested credential data flag was not set";
  // The next 16 bytes for the AAGUID are ignored.
  constexpr size_t length_offset = 53;
  CHECK_GE(auth_data.size(), length_offset + 2)
      << "authData does not fit the attested credential data length";
  size_t credential_id_length =
      256u * auth_data[length_offset] + auth_data[length_offset + 1];
  CHECK_GE(auth_data.size(), length_offset + 2 + credential_id_length)
      << "authData does not fit the attested credential ID";
  ByteVector credential_id(
      auth_data.begin() + length_offset + 2,
      auth_data.begin() + length_offset + 2 + credential_id_length);
  device_tracker->GetCounterChecker()->RegisterCounter(credential_id,
                                                       signature_counter);

  // This ByteVector can have extraneous data for extensions.
  ByteVector cose_key(
      auth_data.begin() + length_offset + 2 + credential_id_length,
      auth_data.end());
  size_t cose_key_size =
      PubKeyDuplicateCheck(device_tracker->GetKeyChecker(), cose_key);
  bool has_extension_flag = flags & 0x80;
  CHECK(has_extension_flag == (cose_key_size < cose_key.size()))
      << "extension flag not matching response";
  ByteVector extension_data(cose_key.begin() + cose_key_size, cose_key.end());
  CheckExtensions(extension_data);

  map_iter = decoded_map.find(CborInt(MakeCredentialResponse::kAttStmt));
  CHECK(map_iter != decoded_map.end())
      << "no attStmt (key 3) in MakeCredential response";

  // TODO(kaczmarczyck) more specific checks depending on the format (in 1)
  if (fmt == "packed") {
    // The attStmt is not necessarily a Byte Array as specified.
    // Testing again for the WebAuthn specification.
    CHECK(map_iter->second.is_map())
        << "attStmt for fmt \"packed\" is not a map";
    const auto& att_stmt = map_iter->second.GetMap();

    auto inner_iter = att_stmt.find(cbor::Value("alg"));
    CHECK(inner_iter != decoded_map.end())
        << "attStmt for fmt \"packed\" does not contain key \"alg\"";
    CHECK(inner_iter->second.is_integer())
        << "\"alg\" in attStmt for fmt \"packed\" is not an integer";
    int64_t alg = inner_iter->second.GetInteger();

    inner_iter = att_stmt.find(cbor::Value("sig"));
    CHECK(inner_iter != decoded_map.end())
        << "attStmt for fmt \"packed\" does not contain key \"sig\"";
    CHECK(inner_iter->second.is_bytestring())
        << "\"sig\" in attStmt for fmt \"packed\" is not a bytestring";
    if (alg == static_cast<int>(Algorithm::kEs256Algorithm)) {
      device_tracker->GetKeyChecker()->CheckKey(
          crypto_utility::ExtractEcdsaSignatureR(
              inner_iter->second.GetBytestring()));
    }
  }

  for (const auto& map_entry : decoded_map) {
    if (map_entry.first.is_unsigned()) {
      const int64_t map_key = map_entry.first.GetUnsigned();
      if (!MakeCredentialResponseContains(map_key)) {
        device_tracker->AddObservation(absl::StrCat(
            "Received unspecified MakeCredential map key ", map_key, "."));
      }
    } else {
      device_tracker->AddObservation(
          "Some MakeCredential map keys are not unsigned.");
    }
  }

  return decoded_response->Clone();
}

absl::variant<cbor::Value, Status> GetAssertionPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request) {
  auto encoded_request = cbor::Writer::Write(request);
  CHECK(encoded_request.has_value()) << "encoding went wrong - TEST SUITE BUG";

  bool requires_up = ExtractUpOptionFromGetAssertionRequest(request);
  ByteVector resp_cbor;
  Status status =
      device->ExchangeCbor(Command::kAuthenticatorGetAssertion,
                           *encoded_request, requires_up, &resp_cbor);
  if (status != Status::kErrNone) {
    return status;
  }

  absl::optional<cbor::Value> decoded_response = cbor::Reader::Read(resp_cbor);
  CHECK(decoded_response.has_value()) << "CBOR decoding failed";
  CHECK(decoded_response->is_map()) << "CBOR response is not a map";
  const auto& decoded_map = decoded_response->GetMap();

  auto map_iter = decoded_map.find(CborInt(GetAssertionResponse::kCredential));
  cbor::Value::BinaryValue credential_id;
  if (map_iter == decoded_map.end()) {
    // Allow list length 1 can be enforced here because only then is not
    // including the credential in the response in key 1 allowed.
    credential_id = ExtractUniqueCredentialFromAllowList(request);
  } else {
    CHECK(map_iter->second.is_map())
        << "PublicKeyCredentialDescriptor is not a map";
    const auto& cred_descriptor = map_iter->second.GetMap();
    auto inner_iter = cred_descriptor.find(cbor::Value("id"));
    CHECK(inner_iter != decoded_map.end())
        << "PublicKeyCredentialDescriptor exists, but has no key \"id\"";
    CHECK(inner_iter->second.is_bytestring())
        << "\"id\" in PublicKeyCredentialDescriptor is not a bytestring";
    credential_id = inner_iter->second.GetBytestring();
  }

  map_iter = decoded_map.find(CborInt(GetAssertionResponse::kAuthData));
  CHECK(map_iter != decoded_map.end())
      << "no authData (key 2) in GetAssertion response";
  CHECK(map_iter->second.is_bytestring())
      << "authData entry is not a bytestring";
  cbor::Value::BinaryValue auth_data = map_iter->second.GetBytestring();
  CHECK_GE(auth_data.size(), 32u)
      << "authData is too small to fit the relying party ID hash";
  ByteVector expected_rp_id_hash =
      crypto_utility::Sha256Hash(ExtractRpIdFromGetAssertionRequest(request));
  CHECK_EQ(expected_rp_id_hash.size(), 32u)
      << "relying party ID hash is not 32 byte";
  CHECK(std::equal(expected_rp_id_hash.begin(), expected_rp_id_hash.end(),
                   auth_data.begin()))
      << "unexpected relying party ID hash";

  CHECK_GE(auth_data.size(), 33u) << "authData does not fit the flags";
  uint8_t flags = auth_data[32];
  // Contrary to MakeCredential, explicitly setting "up" to false is okay.
  CHECK(flags & 0x05 || !requires_up) << "silent assertion not requested";
  // GetAssertion does not need a user presence after verification.
  if (IsKeyInRequest(
          request, static_cast<int>(GetAssertionParameters::kPinUvAuthParam))) {
    CHECK(flags & 0x04) << "no user verification flag despite auth token";
  }

  CHECK_GE(auth_data.size(), 37u) << "authData does not fit the counter";
  uint32_t signature_counter = absl::big_endian::Load32(auth_data.data() + 33);
  device_tracker->GetCounterChecker()->CheckCounter(credential_id,
                                                    signature_counter);

  size_t extension_data_size = auth_data.size() - 37;
  bool has_extension_flag = flags & 0x80;
  CHECK(has_extension_flag == (extension_data_size > 0))
      << "extension flag not matching response";
  ByteVector extension_data(auth_data.begin() + 37, auth_data.end());
  CheckExtensions(extension_data);

  map_iter = decoded_map.find(CborInt(GetAssertionResponse::kSignature));
  CHECK(map_iter != decoded_map.end())
      << "no signature (key 3) in GetAssertion response";
  CHECK(map_iter->second.is_bytestring())
      << "signature entry is not a bytestring";
  auto printed_sig = map_iter->second.GetBytestring();
  // Since we don't send random challenges, what about deterministic signatures?
  // key_checker->CheckKey(
  // crypto_utility::ExtractEcdsaSignatureR(map_iter->second.GetBytestring()));
  // TODO(kaczmarczyck) depending on algorithm, check for other duplicates
  // What is the intended way to remember the algorithm used? Just somehow store
  // it along with the PublicKeyCredentialSource? What about non-resident keys?

  map_iter = decoded_map.find(CborInt(GetAssertionResponse::kUser));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_map()) << "user entry is not a map";
    const auto& user = map_iter->second.GetMap();

    auto inner_iter = user.find(cbor::Value("id"));
    CHECK(inner_iter != user.end())
        << "public key credential user entity does not contain key \"id\"";
    CHECK(inner_iter->second.is_bytestring())
        << "\"id\" in user entity is not a bytestring";

    inner_iter = user.find(cbor::Value("name"));
    if (inner_iter != user.end()) {
      CHECK(inner_iter->second.is_string())
          << "\"name\" in user entity is not a string";
    }

    inner_iter = user.find(cbor::Value("displayName"));
    if (inner_iter != user.end()) {
      CHECK(inner_iter->second.is_string())
          << "\"displayName\" in user entity is not a string";
    }

    inner_iter = user.find(cbor::Value("icon"));
    if (inner_iter != user.end()) {
      CHECK(inner_iter->second.is_string())
          << "\"icon\" in user entity is not a string";
    }
  }

  map_iter =
      decoded_map.find(CborInt(GetAssertionResponse::kNumberOfCredentials));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "number of credentials entry is not an unsigned";
  }

  for (const auto& map_entry : decoded_map) {
    if (map_entry.first.is_unsigned()) {
      const int64_t map_key = map_entry.first.GetUnsigned();
      if (!GetAssertionResponseContains(map_key)) {
        device_tracker->AddObservation(absl::StrCat(
            "Received unspecified GetAssertion map key ", map_key, "."));
      }
    } else {
      device_tracker->AddObservation(
          "Some GetAssertion map keys are not unsigned.");
    }
  }

  return decoded_response->Clone();
}

absl::variant<cbor::Value, Status> GetNextAssertionPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request) {
  // TODO(kaczmarczyck) reuse the assertion checks
  return cbor::Value();
}

absl::variant<cbor::Value, Status> GetInfoPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker) {
  ByteVector req_cbor;
  ByteVector resp_cbor;
  Status status = device->ExchangeCbor(Command::kAuthenticatorGetInfo, req_cbor,
                                       false, &resp_cbor);
  if (status != Status::kErrNone) {
    return status;
  }

  absl::optional<cbor::Value> decoded_response = cbor::Reader::Read(resp_cbor);
  CHECK(decoded_response.has_value()) << "CBOR decoding failed";
  CHECK(decoded_response->is_map()) << "CBOR response is not a map";
  const auto& decoded_map = decoded_response->GetMap();

  auto map_iter = decoded_map.find(CborInt(InfoMember::kVersions));
  CHECK(map_iter != decoded_map.end())
      << "no versions (key 1) included in GetInfo response";
  CHECK(map_iter->second.is_array()) << "versions entry is not an array";
  absl::flat_hash_set<std::string> versions_set;
  for (const auto& version : map_iter->second.GetArray()) {
    CHECK(version.is_string()) << "versions elements are not strings";
    CHECK_EQ(versions_set.count(version.GetString()), 0u)
        << "duplicate version in info";
    versions_set.insert(version.GetString());
  }
  CHECK(versions_set.find("FIDO_2_0") != versions_set.end())
      << "versions does not contain \"FIDO_2_0\"";

  map_iter = decoded_map.find(CborInt(InfoMember::kExtensions));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array()) << "extensions entry is not an array";
    absl::flat_hash_set<std::string> extensions_set;
    for (const auto& extension : map_iter->second.GetArray()) {
      CHECK(extension.is_string()) << "extensions elements are not strings";
      CHECK_EQ(extensions_set.count(extension.GetString()), 0u)
          << "duplicate extension in info";
      extensions_set.insert(extension.GetString());
    }
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kAaguid));
  CHECK(map_iter != decoded_map.end())
      << "no AAGUID (key 3) in GetInfo response";
  CHECK(map_iter->second.is_bytestring()) << "aaguid entry is not a bytestring";

  map_iter = decoded_map.find(CborInt(InfoMember::kOptions));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_map()) << "options entry is not a map";
    for (const auto& options_iter : map_iter->second.GetMap()) {
      CHECK(options_iter.first.is_string()) << "option name is not a string";
      CHECK(options_iter.second.is_bool()) << "option value is not a boolean";
    }
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMaxMsgSize));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxMsgSize entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kPinUvAuthProtocols));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array())
        << "pinUvAuthProtocols entry is not an array";
    for (const auto& protocol : map_iter->second.GetArray()) {
      CHECK(protocol.is_unsigned())
          << "pinUvAuthProtocols elements are not unsigned";
    }
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMaxCredentialCountInList));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredentialCountInList entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMaxCredentialIdLength));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredentialIdLength entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kTransports));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array()) << "transports entry is not an array";
    absl::flat_hash_set<std::string> transports_set;
    for (const auto& transport : map_iter->second.GetArray()) {
      CHECK(transport.is_string()) << "transports elements are not strings";
      CHECK_EQ(transports_set.count(transport.GetString()), 0u)
          << "duplicate transport in info";
      transports_set.insert(transport.GetString());
    }
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kAlgorithms));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array()) << "algorithms entry is not an array";
    absl::flat_hash_set<int> algorithms_set;
    for (const auto& algorithm : map_iter->second.GetArray()) {
      CHECK(algorithm.is_map()) << "algorithms elements are not maps";
      const auto& algorithm_map = algorithm.GetMap();
      auto inner_iter = algorithm_map.find(cbor::Value("type"));
      CHECK(inner_iter != algorithm_map.end())
          << "algorithm did not contain key \"type\"";
      CHECK(inner_iter->second.is_string())
          << "\"type\" in algorithm is not a string";
      CHECK(inner_iter->second.GetString() == "public-key")
          << "\"type\" in algorithm is not \"public-key\"";

      inner_iter = algorithm_map.find(cbor::Value("alg"));
      CHECK(inner_iter != algorithm_map.end())
          << "algorithm did not contain key \"alg\"";
      CHECK(inner_iter->second.is_integer())
          << "\"alg\" in algorithm is not an integer";
      CHECK_EQ(algorithms_set.count(inner_iter->second.GetInteger()), 0u)
          << "duplicate algorithm in info";
      algorithms_set.insert(inner_iter->second.GetInteger());
    }
  }

  map_iter =
      decoded_map.find(CborInt(InfoMember::kMaxSerializedLargeBlobArray));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxSerializedLargeBlobArray entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 1024)
        << "maxSerializedLargeBlobArray is too small";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kForcePinChange));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_bool()) << "forcePINChangeentry is not a bool";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMinPinLength));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "minPINLength entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 4) << "minPINLength is too small";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kFirmwareVersion));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "firmwareVersion entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMaxCredBlobLength));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredBlobLength entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 32)
        << "maxCredBlobLength is too small";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kMaxRpIdsForSetMinPinLength));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxRPIDsForSetMinPINLength entry is not an unsigned";
  }

  map_iter =
      decoded_map.find(CborInt(InfoMember::kPreferredPlatformUvAttempts));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "preferredPlatformUvAttempts entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kUvModality));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "uvModality entry is not an unsigned";
  }

  map_iter = decoded_map.find(CborInt(InfoMember::kCertifications));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_map()) << "certifications entry is not a map";
  }

  map_iter =
      decoded_map.find(CborInt(InfoMember::kRemainingDiscoverableCredentials));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "remainingDiscoverableCredentials entry is not an unsigned";
  }

  map_iter =
      decoded_map.find(CborInt(InfoMember::kVendorPrototypeConfigCommands));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array())
        << "vendorPrototypeConfigCommands entry is not an array";
    for (const auto& command : map_iter->second.GetArray()) {
      CHECK(command.is_unsigned())
          << "vendorPrototypeConfigCommands elements are not unsigned";
    }
  }

  for (const auto& map_entry : decoded_map) {
    if (map_entry.first.is_unsigned()) {
      const int64_t map_key = map_entry.first.GetUnsigned();
      if (!InfoMemberContains(map_key)) {
        device_tracker->AddObservation(
            absl::StrCat("Received unspecified GetInfo map key ",
                         absl::Hex(map_key, absl::kZeroPad2), "."));
      }
    } else {
      device_tracker->AddObservation("Some GetInfo map keys are not unsigned.");
    }
  }

  device_tracker->Initialize(decoded_map);
  return decoded_response->Clone();
}

absl::variant<cbor::Value, Status> AuthenticatorClientPinPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request) {
  auto encoded_request = cbor::Writer::Write(request);
  CHECK(encoded_request.has_value()) << "encoding went wrong - TEST SUITE BUG";

  ByteVector resp_cbor;
  Status status = device->ExchangeCbor(Command::kAuthenticatorClientPIN,
                                       *encoded_request, false, &resp_cbor);
  if (status != Status::kErrNone) {
    return status;
  }

  PinSubCommand subcommand = ExtractPinSubCommand(request);
  bool has_response_cbor = subcommand != PinSubCommand::kSetPin &&
                           subcommand != PinSubCommand::kChangePin;
  absl::optional<cbor::Value> decoded_response = cbor::Reader::Read(resp_cbor);
  if (has_response_cbor) {
    CHECK(decoded_response.has_value()) << "CBOR decoding failed";
    CHECK(decoded_response->is_map()) << "CBOR response is not a map";
  } else {
    CHECK(resp_cbor.empty()) << "CBOR response not empty";
  }
  const auto& decoded_map = has_response_cbor
                                ? decoded_response->GetMap()
                                : cbor::Value(cbor::Value::Type::MAP).GetMap();

  absl::flat_hash_set<ClientPinResponse> allowed_map_keys;

  switch (subcommand) {
    case PinSubCommand::kGetPinRetries: {
      allowed_map_keys.insert(ClientPinResponse::kPinRetries);
      auto map_iter = decoded_map.find(CborInt(ClientPinResponse::kPinRetries));
      CHECK(map_iter != decoded_map.end())
          << "no PIN retries (key 3) included in PIN protocol response";
      CHECK(map_iter->second.is_unsigned())
          << "PIN retries entry is not an unsigned";
      allowed_map_keys.insert(ClientPinResponse::kPowerCycleState);
      map_iter = decoded_map.find(CborInt(ClientPinResponse::kPowerCycleState));
      if (map_iter != decoded_map.end()) {
        CHECK(map_iter->second.is_bool())
            << "powerCycleState entry is not a boolean";
      }
      break;
    }
    case PinSubCommand::kGetKeyAgreement: {
      allowed_map_keys.insert(ClientPinResponse::kKeyAgreement);
      auto map_iter =
          decoded_map.find(CborInt(ClientPinResponse::kKeyAgreement));
      CHECK(map_iter != decoded_map.end())
          << "no KeyAgreement (key 1) in PIN protocol response";
      CHECK(map_iter->second.is_map()) << "KeyAgreement entry is not a map";
      const auto& cose_key = map_iter->second.GetMap();
      crypto_utility::CheckEcdhCoseKey(cose_key);
      break;
    }
    case PinSubCommand::kSetPin: {
      break;
    }
    case PinSubCommand::kChangePin: {
      break;
    }
    case PinSubCommand::kGetPinToken: {
      allowed_map_keys.insert(ClientPinResponse::kPinUvAuthToken);
      auto map_iter =
          decoded_map.find(CborInt(ClientPinResponse::kPinUvAuthToken));
      CHECK(map_iter != decoded_map.end())
          << "no pinUvAuthToken (key 2) in PIN protocol response";
      CHECK(map_iter->second.is_bytestring())
          << "pinUvAuthToken entry is not a bytestring";
      break;
    }
    case PinSubCommand::kGetPinUvAuthTokenUsingUvWithPermissions: {
      allowed_map_keys.insert(ClientPinResponse::kPinUvAuthToken);
      auto map_iter =
          decoded_map.find(CborInt(ClientPinResponse::kPinUvAuthToken));
      CHECK(map_iter != decoded_map.end())
          << "no pinUvAuthToken (key 2) in PIN protocol response";
      CHECK(map_iter->second.is_bytestring())
          << "pinUvAuthToken entry is not a bytestring";
      break;
    }
    case PinSubCommand::kGetUvRetries: {
      allowed_map_keys.insert(ClientPinResponse::kPowerCycleState);
      auto map_iter =
          decoded_map.find(CborInt(ClientPinResponse::kPowerCycleState));
      if (map_iter != decoded_map.end()) {
        CHECK(map_iter->second.is_bool())
            << "powerCycleState entry is not a boolean";
      }
      allowed_map_keys.insert(ClientPinResponse::kUvRetries);
      map_iter = decoded_map.find(CborInt(ClientPinResponse::kUvRetries));
      CHECK(map_iter != decoded_map.end())
          << "no UV retries (key 5) included in PIN protocol response";
      CHECK(map_iter->second.is_unsigned())
          << "UV retries entry is not an unsigned";
      break;
    }
    case PinSubCommand::kGetPinUvAuthTokenUsingPinWithPermissions: {
      allowed_map_keys.insert(ClientPinResponse::kPinUvAuthToken);
      auto map_iter =
          decoded_map.find(CborInt(ClientPinResponse::kPinUvAuthToken));
      CHECK(map_iter != decoded_map.end())
          << "no pinUvAuthToken (key 2) in PIN protocol response";
      CHECK(map_iter->second.is_bytestring())
          << "pinUvAuthToken entry is not a bytestring";
      break;
    }
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }

  // Check for unexpected map keys.
  if (has_response_cbor) {
    for (const auto& map_entry : decoded_map) {
      if (map_entry.first.is_unsigned()) {
        const int64_t map_key = map_entry.first.GetUnsigned();
        if (!ClientPinResponseContains(map_key) ||
            !allowed_map_keys.contains(
                static_cast<ClientPinResponse>(map_key))) {
          device_tracker->AddObservation(absl::StrCat(
              "Received unspecified ClientPin map key ", map_key, "."));
        }
      } else {
        device_tracker->AddObservation(
            "Some ClientPin map keys are not unsigned.");
      }
    }
  }

  return has_response_cbor ? decoded_response->Clone() : cbor::Value();
}

// Be careful: vendor-specific things might happen here.
// Yubico i.e. only allows for resets in the first 5 seconds after powerup.
absl::variant<cbor::Value, Status> ResetPositiveTest(DeviceInterface* device) {
  ByteVector req_cbor;
  ByteVector resp_cbor;
  Status status = device->ExchangeCbor(Command::kAuthenticatorReset, req_cbor,
                                       true, &resp_cbor);
  if (status != Status::kErrNone) {
    return status;
  }
  CHECK(resp_cbor.empty()) << "CBOR response not empty";
  return cbor::Value();
}

absl::variant<cbor::Value, Status>
AuthenticatorCredentialManagementPositiveTest(DeviceInterface* device,
                                              DeviceTracker* device_tracker,
                                              const cbor::Value& request) {
  auto encoded_request = cbor::Writer::Write(request);
  CHECK(encoded_request.has_value()) << "encoding went wrong - TEST SUITE BUG";

  ByteVector resp_cbor;
  Status status =
      device->ExchangeCbor(Command::kAuthenticatorCredentialManagement,
                           *encoded_request, false, &resp_cbor);
  if (status != Status::kErrNone) {
    return status;
  }

  ManagementSubCommand subcommand = ExtractManagementSubCommand(request);
  if (subcommand == ManagementSubCommand::kDeleteCredential ||
      subcommand == ManagementSubCommand::kUpdateUserInformation) {
    TRUE_OR_RETURN(resp_cbor.empty(), "The CBOR response was not empty.");
    return cbor::Value();
  }

  absl::optional<cbor::Value> decoded_response = cbor::Reader::Read(resp_cbor);
  TRUE_OR_RETURN(decoded_response.has_value(), "CBOR decoding failed.");
  TRUE_OR_RETURN(decoded_response->is_map(), "CBOR response is not a map.");
  const auto& decoded_map = decoded_response->GetMap();
  absl::flat_hash_set<CredentialManagementResponse> allowed_map_keys;

  switch (subcommand) {
    case ManagementSubCommand::kGetCredsMetadata: {
      allowed_map_keys.insert(
          CredentialManagementResponse::kExistingResidentCredentialsCount);
      auto map_iter = decoded_map.find(CborInt(
          CredentialManagementResponse::kExistingResidentCredentialsCount));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No existingResidentCredentialsCount in "
                     "CredentialManagement response.");
      TRUE_OR_RETURN(
          map_iter->second.is_unsigned(),
          "existingResidentCredentialsCountentry is not an unsigned.");
      allowed_map_keys.insert(
          CredentialManagementResponse::
              kMaxPossibleRemainingResidentCredentialsCount);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::
                      kMaxPossibleRemainingResidentCredentialsCount));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No maxPossibleRemainingResidentCredentialsCount in "
                     "CredentialManagement response.");
      TRUE_OR_RETURN(
          map_iter->second.is_unsigned(),
          "maxPossibleRemainingResidentCredentialsCount is not an unsigned.");
      break;
    }
    case ManagementSubCommand::kEnumerateRpsBegin: {
      allowed_map_keys.insert(CredentialManagementResponse::kRp);
      auto map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kRp));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No rp in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "rp is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kRpIdHash);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kRpIdHash));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No rpIDHash in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_bytestring(),
                     "rpIDHash is not a bytestring.");
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kTotalRps));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No totalRPs in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_unsigned(),
                     "totalRPs is not an unsigned.");
      break;
    }
    case ManagementSubCommand::kEnumerateRpsGetNextRp: {
      allowed_map_keys.insert(CredentialManagementResponse::kRp);
      auto map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kRp));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No rp in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "rp is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kRpIdHash);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kRpIdHash));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No rpIDHash in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_bytestring(),
                     "rpIDHash is not a bytestring.");
      break;
    }
    case ManagementSubCommand::kEnumerateCredentialsBegin: {
      allowed_map_keys.insert(CredentialManagementResponse::kUser);
      auto map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kUser));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No user in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "user is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kCredentialId);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::kCredentialId));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No credentialID in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "credentialID is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kPublicKey);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kPublicKey));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No publicKey in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "publicKey is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kTotalCredentials);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::kTotalCredentials));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No publicKey in totalCredentials response.");
      TRUE_OR_RETURN(map_iter->second.is_unsigned(),
                     "totalCredentials is not an unsigned.");
      allowed_map_keys.insert(CredentialManagementResponse::kCredProtect);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kCredProtect));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No credProtect in totalCredentials response.");
      TRUE_OR_RETURN(map_iter->second.is_unsigned(),
                     "credProtect is not an unsigned.");
      allowed_map_keys.insert(CredentialManagementResponse::kLargeBlobKey);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::kLargeBlobKey));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No largeBlobKey in totalCredentials response.");
      TRUE_OR_RETURN(map_iter->second.is_bytestring(),
                     "largeBlobKey is not a bytestring.");
      break;
    }
    case ManagementSubCommand::kEnumerateCredentialsGetNextCredential: {
      allowed_map_keys.insert(CredentialManagementResponse::kUser);
      auto map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kUser));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No user in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "user is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kCredentialId);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::kCredentialId));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No credentialID in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "credentialID is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kPublicKey);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kPublicKey));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No publicKey in CredentialManagement response.");
      TRUE_OR_RETURN(map_iter->second.is_map(), "publicKey is not a map.");
      allowed_map_keys.insert(CredentialManagementResponse::kCredProtect);
      map_iter =
          decoded_map.find(CborInt(CredentialManagementResponse::kCredProtect));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No credProtect in totalCredentials response.");
      TRUE_OR_RETURN(map_iter->second.is_unsigned(),
                     "credProtect is not an unsigned.");
      allowed_map_keys.insert(CredentialManagementResponse::kLargeBlobKey);
      map_iter = decoded_map.find(
          CborInt(CredentialManagementResponse::kLargeBlobKey));
      TRUE_OR_RETURN(map_iter != decoded_map.end(),
                     "No largeBlobKey in totalCredentials response.");
      TRUE_OR_RETURN(map_iter->second.is_bytestring(),
                     "largeBlobKey is not a bytestring.");
      break;
    }
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }

  // Check for unexpected map keys.
  for (const auto& map_entry : decoded_map) {
    if (map_entry.first.is_unsigned()) {
      const int64_t map_key = map_entry.first.GetUnsigned();
      if (!CredentialManagementResponseContains(map_key) ||
          !allowed_map_keys.contains(
              static_cast<CredentialManagementResponse>(map_key))) {
        device_tracker->AddObservation(
            absl::StrCat("Received unspecified CredentialManagement map key ",
                         map_key, "."));
      }
    } else {
      device_tracker->AddObservation(
          "Some Credential Management map keys are not unsigned.");
    }
  }

  return decoded_response->Clone();
}

Status MakeCredentialNegativeTest(DeviceInterface* device,
                                  const cbor::Value& request,
                                  bool expect_up_check) {
  return GenericNegativeTest(
      device, request, Command::kAuthenticatorMakeCredential, expect_up_check);
}

Status GetAssertionNegativeTest(DeviceInterface* device,
                                const cbor::Value& request,
                                bool expect_up_check) {
  return GenericNegativeTest(
      device, request, Command::kAuthenticatorGetAssertion, expect_up_check);
}

Status GetNextAssertionNegativeTest(DeviceInterface* device,
                                    const cbor::Value& request,
                                    bool expect_up_check) {
  return GenericNegativeTest(device, request,
                             Command::kAuthenticatorGetNextAssertion,
                             expect_up_check);
}

Status GetInfoNegativeTest(DeviceInterface* device, const cbor::Value& request,
                           bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorGetInfo,
                             expect_up_check);
}

Status AuthenticatorClientPinNegativeTest(DeviceInterface* device,
                                          const cbor::Value& request,
                                          bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorClientPIN,
                             expect_up_check);
}

Status ResetNegativeTest(DeviceInterface* device, const cbor::Value& request,
                         bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorReset,
                             expect_up_check);
}

Status CredentialManagementNegativeTest(DeviceInterface* device,
                                        const cbor::Value& request,
                                        bool expect_up_check) {
  return GenericNegativeTest(device, request,
                             Command::kAuthenticatorCredentialManagement,
                             expect_up_check);
}

Status SelectionNegativeTest(DeviceInterface* device,
                             const cbor::Value& request, bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorSelection,
                             expect_up_check);
}

Status LargeBlobsNegativeTest(DeviceInterface* device,
                              const cbor::Value& request,
                              bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorLargeBlobs,
                             expect_up_check);
}

Status AuthenticatorConfigNegativeTest(DeviceInterface* device,
                                       const cbor::Value& request,
                                       bool expect_up_check) {
  return GenericNegativeTest(device, request, Command::kAuthenticatorConfig,
                             expect_up_check);
}

Status GenericNegativeTest(DeviceInterface* device, const cbor::Value& request,
                           Command command, bool expect_up_check) {
  ByteVector req_cbor;
  if (!request.is_none()) {
    auto encoded_request = cbor::Writer::Write(request);
    CHECK(encoded_request.has_value())
        << "encoding went wrong - TEST SUITE BUG";
    req_cbor = encoded_request.value();
  }
  return NonCborNegativeTest(device, req_cbor, command, expect_up_check);
}

Status NonCborNegativeTest(DeviceInterface* device,
                           const ByteVector& request_bytes, Command command,
                           bool expect_up_check) {
  ByteVector resp_cbor;
  return device->ExchangeCbor(command, request_bytes, expect_up_check,
                              &resp_cbor);
}

}  // namespace fido2_commands
}  // namespace fido2_tests

