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

#include "src/cbor_builders.h"

#include "gtest/gtest.h"
#include "src/constants.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace {

TEST(CborBuilders, TestBaseBuilderGetCbor) {
  CborBuilder cbor_builder = CborBuilder();
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestBaseBuilderSetIntKey) {
  CborBuilder cbor_builder = CborBuilder();
  cbor_builder.SetArbitraryMapEntry(1, cbor::Value(2));
  cbor::Value map_1_2 = cbor_builder.GetCbor();
  ASSERT_EQ(map_1_2.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(map_1_2.GetMap().size(), 1);
  cbor::Value key_1(1);
  ASSERT_EQ(map_1_2.GetMap().count(key_1), 1);
  ASSERT_TRUE(map_1_2.GetMap().find(key_1)->second.is_unsigned());
  EXPECT_EQ(map_1_2.GetMap().find(key_1)->second.GetInteger(), 2);
}

TEST(CborBuilders, TestBaseBuilderSetValueKey) {
  CborBuilder cbor_builder = CborBuilder();
  cbor_builder.SetArbitraryMapEntry(cbor::Value(1), cbor::Value(2));
  cbor::Value map_1_2 = cbor_builder.GetCbor();
  ASSERT_EQ(map_1_2.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(map_1_2.GetMap().size(), 1);
  cbor::Value key_1(1);
  ASSERT_EQ(map_1_2.GetMap().count(key_1), 1);
  ASSERT_TRUE(map_1_2.GetMap().find(key_1)->second.is_unsigned());
  EXPECT_EQ(map_1_2.GetMap().find(key_1)->second.GetInteger(), 2);
}

TEST(CborBuilders, TestBaseBuilderRemoveIntKey) {
  CborBuilder cbor_builder = CborBuilder();
  cbor_builder.SetArbitraryMapEntry(1, cbor::Value(2));
  cbor_builder.RemoveArbitraryMapEntry(1);
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestBaseBuilderRemoveValueKey) {
  CborBuilder cbor_builder = CborBuilder();
  cbor_builder.SetArbitraryMapEntry(cbor::Value(1), cbor::Value(2));
  cbor_builder.RemoveArbitraryMapEntry(cbor::Value(1));
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestMakeCredentialCborBuilder) {
  MakeCredentialCborBuilder cbor_builder = MakeCredentialCborBuilder();
  cbor_builder.SetMapEntry(MakeCredentialParameters::kClientDataHash,
                           cbor::Value(2));
  cbor_builder.RemoveMapEntry(MakeCredentialParameters::kClientDataHash);
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestGetAssertionCborBuilder) {
  GetAssertionCborBuilder cbor_builder = GetAssertionCborBuilder();
  cbor_builder.SetMapEntry(GetAssertionParameters::kRpId, cbor::Value(2));
  cbor_builder.RemoveMapEntry(GetAssertionParameters::kRpId);
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestClientPinCborBuilder) {
  AuthenticatorClientPinCborBuilder cbor_builder =
      AuthenticatorClientPinCborBuilder();
  cbor_builder.SetMapEntry(ClientPinParameters::kPinUvAuthProtocol,
                           cbor::Value(2));
  cbor_builder.RemoveMapEntry(ClientPinParameters::kPinUvAuthProtocol);
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

TEST(CborBuilders, TestCredentialManagementCborBuilder) {
  CredentialManagementCborBuilder cbor_builder =
      CredentialManagementCborBuilder();
  cbor_builder.SetMapEntry(CredentialManagementParameters::kSubCommand,
                           cbor::Value(2));
  cbor_builder.RemoveMapEntry(CredentialManagementParameters::kSubCommand);
  cbor::Value blank_map = cbor_builder.GetCbor();
  ASSERT_EQ(blank_map.type(), cbor::Value::Type::MAP);
  EXPECT_EQ(blank_map.GetMap().size(), 0);
}

}  // namespace
}  // namespace fido2_tests

