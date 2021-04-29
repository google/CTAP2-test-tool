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

#include "src/crypto_utility.h"

#include "glog/logging.h"
#include "openssl/aes.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdh.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/pem.h"
#include "openssl/sha.h"
#include "src/constants.h"

namespace fido2_tests {
namespace crypto_utility {

namespace {

constexpr size_t kAuthTokenSize = 16;
constexpr int kCurveName = NID_X9_62_prime256v1;
constexpr int kEcdhKeyType = 2;
constexpr int kCurveParameter = 1;

// This function passes ownership of the generated key to its caller.
bssl::UniquePtr<EC_POINT> EcPointFromPublicCoordinates(
    const EC_GROUP* ec_group, const std::vector<uint8_t>& public_x,
    const std::vector<uint8_t>& public_y) {
  BIGNUM* public_x_bignum =
      BN_bin2bn(public_x.data(), public_x.size(), nullptr);
  CHECK(public_x_bignum != nullptr)
      << "unable to create bignum from x vector - TEST SUITE BUG";
  BIGNUM* public_y_bignum =
      BN_bin2bn(public_y.data(), public_y.size(), nullptr);
  CHECK(public_y_bignum != nullptr)
      << "unable to create bignum from y vector - TEST SUITE BUG";
  bssl::UniquePtr<EC_POINT> public_point(EC_POINT_new(ec_group));
  CHECK(EC_POINT_set_affine_coordinates_GFp(
      ec_group, public_point.get(), public_x_bignum, public_y_bignum, nullptr))
      << "could not set the EC point coordinates provided by the public";
  BN_free(public_x_bignum);
  BN_free(public_y_bignum);
  return public_point;
}

// The cose_public_key_out will be mutated as output.
void WritePublicKeyToCoseMap(const EC_GROUP* ec_group,
                             const EC_POINT* ec_public_key,
                             cbor::Value::MapValue* cose_public_key_out) {
  const int kCoordinateEncodingSize = 32;
  BIGNUM platform_public_key_x_bignum, platform_public_key_y_bignum;
  BN_init(&platform_public_key_x_bignum);
  BN_init(&platform_public_key_y_bignum);
  CHECK(EC_POINT_get_affine_coordinates_GFp(
      ec_group, ec_public_key, &platform_public_key_x_bignum,
      &platform_public_key_y_bignum, nullptr))
      << "unable to get public key coordinates - TEST SUITE BUG";
  int platform_public_key_x_len = BN_num_bytes(&platform_public_key_x_bignum);
  std::vector<uint8_t> platform_public_key_x(kCoordinateEncodingSize, 0);
  CHECK_GE(kCoordinateEncodingSize, platform_public_key_x_len)
      << "COSE key byte representation too big - TEST SUITE BUG";
  CHECK_EQ(
      (int)BN_bn2bin(&platform_public_key_x_bignum,
                     platform_public_key_x.data() + kCoordinateEncodingSize -
                         platform_public_key_x_len),
      platform_public_key_x_len)
      << "bignum to vector conversion failed - TEST SUITE BUG";
  int platform_public_key_y_len = BN_num_bytes(&platform_public_key_y_bignum);
  std::vector<uint8_t> platform_public_key_y(kCoordinateEncodingSize, 0);
  CHECK_GE(kCoordinateEncodingSize, platform_public_key_y_len)
      << "COSE key byte representation too big - TEST SUITE BUG";
  CHECK_EQ(
      (int)BN_bn2bin(&platform_public_key_y_bignum,
                     platform_public_key_y.data() + kCoordinateEncodingSize -
                         platform_public_key_y_len),
      platform_public_key_y_len)
      << "bignum to vector conversion failed - TEST SUITE BUG";

  (*cose_public_key_out)[cbor::Value(1)] = cbor::Value(kEcdhKeyType);
  // Beware here: Despite the algorithm's name, this is not supposed to do
  // SHA256 at the end. The algorithm identifier is only there for backwards
  // compatibility.
  (*cose_public_key_out)[cbor::Value(3)] = CborInt(Algorithm::kEcdhEsHkdf256);
  (*cose_public_key_out)[cbor::Value(-1)] = cbor::Value(kCurveParameter);
  (*cose_public_key_out)[cbor::Value(-2)] = cbor::Value(platform_public_key_x);
  (*cose_public_key_out)[cbor::Value(-3)] = cbor::Value(platform_public_key_y);
}

std::vector<uint8_t> Aes256Cbc(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& message,
                               bool is_encrypt_mode) {
  CHECK(key.size() == 32) << "secret does not have 256 bits";
  CHECK(message.size() % AES_BLOCK_SIZE == 0)
      << "message size is not a multiple of AES block size";
  std::vector<uint8_t> iv(AES_BLOCK_SIZE, 0);
  std::vector<uint8_t> enc_out(message.size(), 0);
  AES_KEY enc_key;
  if (is_encrypt_mode) {
    AES_set_encrypt_key(key.data(), key.size() * 8, &enc_key);
    AES_cbc_encrypt(message.data(), enc_out.data(), message.size(), &enc_key,
                    iv.data(), AES_ENCRYPT);
  } else {
    AES_set_decrypt_key(key.data(), key.size() * 8, &enc_key);
    AES_cbc_encrypt(message.data(), enc_out.data(), message.size(), &enc_key,
                    iv.data(), AES_DECRYPT);
  }
  return enc_out;
}

}  // namespace

cbor::Value::MapValue GenerateExampleEcdhCoseKey() {
  cbor::Value::MapValue example_cose_key;
  example_cose_key[cbor::Value(1)] = cbor::Value(kEcdhKeyType);
  // The spec asks for -25, even though it is not the algorithm in use.
  example_cose_key[cbor::Value(3)] = CborInt(Algorithm::kEcdhEsHkdf256);
  example_cose_key[cbor::Value(-1)] = cbor::Value(kCurveParameter);
  example_cose_key[cbor::Value(-2)] = cbor::Value(cbor::Value::BinaryValue(
      {0xb2, 0x07, 0x17, 0xfb, 0xc7, 0xc8, 0x25, 0x17, 0xf5, 0x11, 0x02,
       0x7d, 0x9e, 0x80, 0x88, 0x8a, 0xbd, 0x33, 0xa1, 0x83, 0x7c, 0xe8,
       0x35, 0xa5, 0x0c, 0xef, 0xfd, 0x4d, 0xea, 0x14, 0x33, 0x7b}));
  example_cose_key[cbor::Value(-3)] = cbor::Value(cbor::Value::BinaryValue(
      {0x9d, 0x13, 0x28, 0x23, 0xed, 0xd8, 0x52, 0xdc, 0xc2, 0x1e, 0x49,
       0x23, 0x16, 0x8d, 0xf9, 0x6f, 0xe6, 0x9e, 0xa5, 0x91, 0xe1, 0xc2,
       0xd1, 0x3e, 0x98, 0xe4, 0x92, 0x06, 0x73, 0xec, 0x31, 0xb0}));
  return example_cose_key;
}

void CheckEcdhCoseKey(const cbor::Value::MapValue& cose_key) {
  cbor::Value::MapValue correct_cose_key = GenerateExampleEcdhCoseKey();

  for (const auto& map_entry : cose_key) {
    auto correct_cose_iter = correct_cose_key.find(map_entry.first);
    CHECK(map_entry.first.is_integer())
        << "COSE key for ECDH has a non-integer key";
    int map_key = map_entry.first.GetInteger();
    CHECK(correct_cose_iter != correct_cose_key.end())
        << "COSE key for ECDH has the invalid key " << map_key;
    CHECK(map_entry.second.type() == correct_cose_iter->second.type())
        << "COSE key for ECDH has an invalid CBOR type at key " << map_key;
    if (map_entry.second.is_integer()) {
      CHECK(map_entry.second.GetInteger() ==
            correct_cose_iter->second.GetInteger())
          << "COSE key for ECDH has an invalid value at key " << map_key;
    }
  }

  for (const auto& correct_entry : correct_cose_key) {
    auto cose_iter = cose_key.find(correct_entry.first);
    CHECK(cose_iter != cose_key.end())
        << "COSE key for ECDH is missing the key "
        << correct_entry.first.GetInteger();
  }
}

std::vector<uint8_t> Aes256CbcDecrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& cipher) {
  return Aes256Cbc(key, cipher, false);
}

std::vector<uint8_t> Aes256CbcEncrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& message) {
  return Aes256Cbc(key, message, true);
}

std::vector<uint8_t> CompleteEcdhHandshake(
    const cbor::Value::MapValue& cose_public_key_in,
    cbor::Value::MapValue* cose_public_key_out) {
  std::vector<uint8_t> public_key_in_x =
      cose_public_key_in.find(cbor::Value(-2))->second.GetBytestring();
  std::vector<uint8_t> public_key_in_y =
      cose_public_key_in.find(cbor::Value(-3))->second.GetBytestring();

  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(kCurveName));
  CHECK(group != nullptr) << "unable to create EC group - TEST SUITE BUG";
  bssl::UniquePtr<EC_POINT> received_point(EcPointFromPublicCoordinates(
      group.get(), public_key_in_x, public_key_in_y));

  bssl::UniquePtr<EC_KEY> generated_key(EC_KEY_new_by_curve_name(kCurveName));
  CHECK(EC_KEY_generate_key(generated_key.get()))
      << "could not generate platform key - TEST SUITE BUG";
  WritePublicKeyToCoseMap(group.get(),
                          EC_KEY_get0_public_key(generated_key.get()),
                          cose_public_key_out);

  size_t field_size = EC_GROUP_get_degree(group.get());
  size_t field_byte_length = (field_size + 7) / 8;
  std::vector<uint8_t> key_product_x(field_byte_length, 0);
  // Without a KDF, the output is the x coordinate of the resulting EC point.
  CHECK(ECDH_compute_key(key_product_x.data(), field_byte_length,
                         received_point.get(), generated_key.get(), nullptr))
      << "unable to generate secret EC key";
  return Sha256Hash(key_product_x);
}

std::vector<uint8_t> ExtractEcdsaSignatureR(
    const std::vector<uint8_t>& ecdsa_signature) {
  bssl::UniquePtr<ECDSA_SIG> decoded_signature(
      ECDSA_SIG_from_bytes(ecdsa_signature.data(), ecdsa_signature.size()));
  CHECK(decoded_signature != nullptr) << "ecdsa signature could not be decoded";
  size_t r_length = BN_num_bytes(decoded_signature->r);
  std::vector<uint8_t> r_bytes(r_length);
  BN_bn2bin(decoded_signature->r, r_bytes.data());
  return r_bytes;
}

std::vector<uint8_t> LeftHmacSha256(const std::vector<uint8_t>& secret,
                                    const std::vector<uint8_t>& message) {
  uint8_t hmac_result[SHA256_DIGEST_LENGTH];
  unsigned result_len;
  HMAC(EVP_sha256(), secret.data(), secret.size(), message.data(),
       message.size(), hmac_result, &result_len);
  CHECK_EQ((int)result_len, SHA256_DIGEST_LENGTH)
      << "unexpected output length of HMAC - TEST SUITE BUG";
  return std::vector<uint8_t>(hmac_result, hmac_result + kAuthTokenSize);
}

std::vector<uint8_t> LeftSha256Hash(const std::vector<uint8_t>& message) {
  uint8_t hash[SHA256_DIGEST_LENGTH];
  SHA256(message.data(), message.size(), hash);
  return std::vector<uint8_t>(hash, hash + kAuthTokenSize);
}

std::vector<uint8_t> Sha256Hash(std::string_view message) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH, 0);
  SHA256(reinterpret_cast<const uint8_t*>(message.data()), message.size(),
         hash.data());
  return hash;
}

std::vector<uint8_t> Sha256Hash(const std::vector<uint8_t>& message) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH, 0);
  SHA256(message.data(), message.size(), hash.data());
  return hash;
}

}  // namespace crypto_utility
}  // namespace fido2_tests

