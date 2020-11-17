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

#include "src/fuzzing/mutator.h"

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

namespace fido2_tests {
namespace {

TEST(Mutator, TestEraseByte) {
  Mutator mutator(10, 0);
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
  std::vector<uint8_t> empty_data = {};
  ASSERT_FALSE(mutator.EraseByte(empty_data, 0));
  ASSERT_TRUE(mutator.EraseByte(data, 10));
  std::vector<uint8_t> expected_mutation = {1, 2, 4, 5, 6, 7, 8};
  EXPECT_EQ(data, expected_mutation);
}

TEST(Mutator, TestInsertByte) {
  Mutator mutator(10, 0);
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
  ASSERT_FALSE(mutator.InsertByte(data, 4));
  ASSERT_TRUE(mutator.InsertByte(data, 10));
  std::vector<uint8_t> expected_mutation = {1, 2, 251, 3, 4, 5, 6, 7, 8};
  EXPECT_EQ(data, expected_mutation);
}

TEST(Mutator, TestShuffleBytes) {
  Mutator mutator(10, 0);
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
  ASSERT_FALSE(mutator.ShuffleBytes(data, 4));
  ASSERT_TRUE(mutator.ShuffleBytes(data, 10));
  std::vector<uint8_t> expected_mutation = {1, 2, 3, 4, 5, 6, 7, 8};
  EXPECT_EQ(data, expected_mutation);
}

TEST(Mutator, TestMutate) {
  Mutator mutator(10, 1);
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8};
  ASSERT_TRUE(mutator.Mutate(data, 10));
  std::vector<uint8_t> expected_mutation = {1, 3, 42, 2, 152, 4, 6, 7};
  EXPECT_EQ(data, expected_mutation);
}

}  // namespace
}  // namespace fido2_tests

