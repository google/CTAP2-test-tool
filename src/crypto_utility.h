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

#ifndef CRYPTO_UTILITY_H_
#define CRYPTO_UTILITY_H_

#include <vector>

#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace crypto_utility {

// Generates a valid ECDH public key and outputs it in COSE key format.
cbor::Value::MapValue GenerateExampleEcdhCoseKey();

// Checks if the ECDH COSE key contains all necessary keys, if it has
// disallowed optional parameters, and if the constants fit.
void CheckEcdhCoseKey(const cbor::Value::MapValue& cose_key);

// Decrypts the given ciphertext using an initialization vector of constant
// zeros and the given key using AES-CBC. Fails if not provided with exactly 256
// bits of key material.
std::vector<uint8_t> Aes256CbcDecrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& cipher);

// Encrypts the given message using an initialization vector of constant zeros
// and the given key using AES-CBC. Fails if not provided with exactly 256 bits
// of key material.
std::vector<uint8_t> Aes256CbcEncrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& message);

// Generates a public/private ECDH key pair and completes the key-agreement
// using cose_public_key_in as the peer's public key. Returns the shared secret
// (i.e. the SHA256 of big-endian encoding of the x-coordinate of the shared
// point) and writes the generated public key, in COSE format, to
// cose_public_key_out.
std::vector<uint8_t> CompleteEcdhHandshake(
    const cbor::Value::MapValue& cose_public_key_in,
    cbor::Value::MapValue* cose_public_key_out);

// Parses ecdsa_signature as an ASN.1 encoded, ECDSA signature and returns the
// big-endian encoding of the contained r value. Crashes on parse error.
std::vector<uint8_t> ExtractEcdsaSignatureR(
    const std::vector<uint8_t>& ecdsa_signature);

// Returns the first 16 bytes of an HMAC using SHA256, using the given secret
// and message.
std::vector<uint8_t> LeftHmacSha256(const std::vector<uint8_t>& secret,
                                    const std::vector<uint8_t>& message);

// Returns the first 16 bytes of the SHA256 of given message.
std::vector<uint8_t> LeftSha256Hash(const std::vector<uint8_t>& message);

// Returns the SHA256 of given message of type string.
std::vector<uint8_t> Sha256Hash(std::string_view message);

// Returns the SHA256 of given message of type byte vector.
std::vector<uint8_t> Sha256Hash(const std::vector<uint8_t>& message);

}  // namespace crypto_utility
}  // namespace fido2_tests

#endif  // CRYPTO_UTILITY_H_

