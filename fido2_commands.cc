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

#include "fido2_commands.h"

#include <cstdint>
#include <iostream>

#include "absl/container/flat_hash_set.h"
#include "absl/types/optional.h"
#include "constants.h"
#include "crypto_utility.h"
#include "glog/logging.h"
#include "parameter_check.h"
#include "third_party/chromium_components_cbor/reader.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {
namespace fido2_commands {

using ByteVector = std::vector<uint8_t>;

namespace {
void CompareExtensions(const cbor::Value& request, int map_key,
                       const ByteVector& extension_data) {
  if (extension_data.empty()) {
    return;
  }
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(cbor::Value(map_key));
  CHECK(req_iter != request_map.end()) << "unrequested extension in response";
  CHECK(req_iter->second.is_map())
      << "extensions in request are not a map - TEST SUITE BUG";
  const auto& request_extensions = req_iter->second.GetMap();

  absl::optional<cbor::Value> extensions = cbor::Reader::Read(extension_data);
  CHECK(extensions.has_value()) << "CBOR decoding of extensions failed";
  CHECK(extensions->is_map()) << "extensions response is not a map";
  const auto& response_extensions = extensions->GetMap();

  for (const auto& extension_entry : response_extensions) {
    auto extension_iter = request_extensions.find(extension_entry.first);
    CHECK(extension_iter != request_extensions.end())
        << "response has the extra extension "
        << extension_entry.first.GetString();
  }
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
  auto req_iter = request_map.find(cbor::Value(2));
  CHECK(req_iter != request_map.end()) << "2 not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_map()) << "entry 2 is not a map - TEST SUITE BUG";
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
  auto req_iter = request_map.find(cbor::Value(1));
  CHECK(req_iter != request_map.end()) << "1 not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_string())
      << "entry 2 is not a string - TEST SUITE BUG";
  return req_iter->second.GetString();
}

PinSubCommand ExtractSubCommandFromClientPinRequest(
    const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(cbor::Value(2));
  CHECK(req_iter != request_map.end()) << "2 not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_unsigned())
      << "entry 2 is not an unsigned - TEST SUITE BUG";
  return static_cast<PinSubCommand>(req_iter->second.GetUnsigned());
}

cbor::Value::BinaryValue ExtractUniqueCredentialFromAllowList(
    const cbor::Value& request) {
  CHECK(request.is_map()) << "request is not a map - TEST SUITE BUG";
  const auto& request_map = request.GetMap();
  auto req_iter = request_map.find(cbor::Value(3));
  CHECK(req_iter != request_map.end()) << "3 not in request - TEST SUITE BUG";
  CHECK(req_iter->second.is_array())
      << "entry 3 is not an array - TEST SUITE BUG";
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
  auto req_iter = request_map.find(cbor::Value(5));
  if (req_iter == request_map.end()) {
    return true;
  }
  CHECK(req_iter->second.is_map()) << "entry 5 is not a map - TEST SUITE BUG";
  const auto& inner_map = req_iter->second.GetMap();
  auto options_iter = inner_map.find(cbor::Value("up"));
  if (options_iter == inner_map.end()) {
    return true;
  }
  CHECK(options_iter->second.is_bool())
      << "\"up\" is not a boolean - TEST SUITE BUG";
  return options_iter->second.GetBool();
}
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

  auto map_iter = decoded_map.find(cbor::Value(1));
  CHECK(map_iter != decoded_map.end())
      << "no fmt (key 1) in MakeCredential response";
  CHECK(map_iter->second.is_string()) << "fmt is not a string";
  std::string fmt = map_iter->second.GetString();

  map_iter = decoded_map.find(cbor::Value(2));
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
  if (IsKeyInRequest(request, 8)) {
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
  CompareExtensions(request, 6, extension_data);

  map_iter = decoded_map.find(cbor::Value(3));
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
    CHECK(map_entry.first.is_unsigned()) << "some map keys are not unsigned";
    const int64_t map_key = map_entry.first.GetUnsigned();
    CHECK(map_key >= 1 && map_key <= 3) << "there are unspecified map keys";
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

  auto map_iter = decoded_map.find(cbor::Value(1));
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

  map_iter = decoded_map.find(cbor::Value(2));
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
  if (IsKeyInRequest(request, 6)) {
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
  CompareExtensions(request, 4, extension_data);

  map_iter = decoded_map.find(cbor::Value(3));
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

  map_iter = decoded_map.find(cbor::Value(4));
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

  map_iter = decoded_map.find(cbor::Value(5));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "number of credentials entry is not an unsigned";
  }

  for (const auto& map_entry : decoded_map) {
    CHECK(map_entry.first.is_unsigned()) << "some map keys are not unsigned";
    const int64_t map_key = map_entry.first.GetUnsigned();
    CHECK(map_key >= 1 && map_key <= 5) << "there are unspecified map keys";
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
    DeviceInterface* device) {
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

  auto map_iter = decoded_map.find(cbor::Value(0x01));
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

  map_iter = decoded_map.find(cbor::Value(0x02));
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

  map_iter = decoded_map.find(cbor::Value(0x03));
  CHECK(map_iter != decoded_map.end())
      << "no AAGUID (key 3) in GetInfo response";
  CHECK(map_iter->second.is_bytestring()) << "aaguid entry is not a bytestring";

  map_iter = decoded_map.find(cbor::Value(0x04));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_map()) << "options entry is not a map";
    for (const auto& options_iter : map_iter->second.GetMap()) {
      CHECK(options_iter.first.is_string()) << "option name is not a string";
      CHECK(options_iter.second.is_bool()) << "option value is not a boolean";
    }
  }

  map_iter = decoded_map.find(cbor::Value(0x05));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxMsgSize entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x06));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_array()) << "pinProtocols entry is not an array";
    for (const auto& extension : map_iter->second.GetArray()) {
      CHECK(extension.is_unsigned())
          << "pinProtocols elements are not unsigned";
    }
  }

  map_iter = decoded_map.find(cbor::Value(0x07));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredentialCountInList entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x08));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredentialIdLength entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x09));
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

  map_iter = decoded_map.find(cbor::Value(0x0A));
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

  map_iter = decoded_map.find(cbor::Value(0x0B));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxSerializedLargeBlobArray entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 1024)
        << "maxSerializedLargeBlobArray is too small";
  }

  map_iter = decoded_map.find(cbor::Value(0x0D));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "minPINLength entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 4)
        << "minPINLength is too small";
  }

  map_iter = decoded_map.find(cbor::Value(0x0E));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "firmwareVersion entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x0F));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxCredBlobLength entry is not an unsigned";
    CHECK_GE(map_iter->second.GetUnsigned(), 32)
        << "maxCredBlobLength is too small";
  }

  map_iter = decoded_map.find(cbor::Value(0x10));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "maxRPIDsForSetMinPINLength entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x11));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "preferredPlatformUvAttempts entry is not an unsigned";
  }

  map_iter = decoded_map.find(cbor::Value(0x12));
  if (map_iter != decoded_map.end()) {
    CHECK(map_iter->second.is_unsigned())
        << "uvModality entry is not an unsigned";
  }

  for (const auto& map_entry : decoded_map) {
    CHECK(map_entry.first.is_unsigned()) << "some map keys are not unsigned";
    const int64_t map_key = map_entry.first.GetUnsigned();
    CHECK(map_key >= 1 && map_key <= 0x12) << "there are unspecified map keys";
  }

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

  PinSubCommand subcommand = ExtractSubCommandFromClientPinRequest(request);
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

  absl::flat_hash_set<int> allowed_map_keys;

  switch (subcommand) {
    case PinSubCommand::kGetPinRetries: {
      allowed_map_keys.insert(3);
      auto map_iter = decoded_map.find(cbor::Value(3));
      CHECK(map_iter != decoded_map.end())
          << "no PIN retries (key 3) included in PIN protocol response";
      CHECK(map_iter->second.is_unsigned())
          << "PIN retries entry is not an unsigned";
      allowed_map_keys.insert(4);
      map_iter = decoded_map.find(cbor::Value(4));
      if (map_iter != decoded_map.end()) {
        CHECK(map_iter->second.is_bool())
            << "powerCycleState entry is not a boolean";
      }
      break;
    }
    case PinSubCommand::kGetKeyAgreement: {
      allowed_map_keys.insert(1);
      auto map_iter = decoded_map.find(cbor::Value(1));
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
    case PinSubCommand::kGetPinUvAuthTokenUsingPin: {
      allowed_map_keys.insert(2);
      auto map_iter = decoded_map.find(cbor::Value(2));
      CHECK(map_iter != decoded_map.end())
          << "no pinUvAuthToken (key 2) in PIN protocol response";
      CHECK(map_iter->second.is_bytestring())
          << "pinUvAuthToken entry is not a bytestring";
      break;
    }
    case PinSubCommand::kGetPinUvAuthTokenUsingUv: {
      allowed_map_keys.insert(2);
      auto map_iter = decoded_map.find(cbor::Value(2));
      CHECK(map_iter != decoded_map.end())
          << "no pinUvAuthToken (key 2) in PIN protocol response";
      CHECK(map_iter->second.is_bytestring())
          << "pinUvAuthToken entry is not a bytestring";
      break;
    }
    case PinSubCommand::kGetUvRetries: {
      allowed_map_keys.insert(4);
      auto map_iter = decoded_map.find(cbor::Value(4));
      if (map_iter != decoded_map.end()) {
        CHECK(map_iter->second.is_bool())
            << "powerCycleState entry is not a boolean";
      }
      allowed_map_keys.insert(5);
      map_iter = decoded_map.find(cbor::Value(5));
      CHECK(map_iter != decoded_map.end())
          << "no UV retries (key 5) included in PIN protocol response";
      CHECK(map_iter->second.is_unsigned())
          << "UV retries entry is not an unsigned";
      break;
    }
  }

  // Check for unexpected map keys.
  if (has_response_cbor) {
    for (const auto& map_entry : decoded_map) {
      CHECK(map_entry.first.is_unsigned()) << "some map keys are not unsigned";
      const int64_t map_key = map_entry.first.GetUnsigned();
      CHECK(allowed_map_keys.find(map_key) != allowed_map_keys.end())
          << "there are unspecified map keys";
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
