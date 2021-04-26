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

#include "src/fuzzing/mutator.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <vector>

#include "gtest/gtest.h"

namespace fido2_tests {
namespace mutator {
namespace {

bool CheckStrictAscending(std::vector<uint8_t> const& data) {
  if (data.empty()) return true;
  for (int i = 1; i < data.size(); ++i) {
    if (data[i] <= data[i - 1]) return false;
  }
  return true;
}

TEST(Mutator, TestEraseByte) {
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<uint8_t> empty_data = {};
  ASSERT_FALSE(mutator::EraseByte(empty_data, /* max_size = */ 0));
  for (int i = 0; i < data.size(); ++i) {
    srand(i);
    size_t expected_current_size = data.size() - 1;
    ASSERT_TRUE(mutator::EraseByte(data, data.size()));
    ASSERT_TRUE(data.size() == expected_current_size);
    EXPECT_TRUE(CheckStrictAscending(data));
  }
}

TEST(Mutator, TestInsertByte) {
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  for (int i = 0; i < 100; ++i) {
    srand(i);
    size_t expected_current_size = data.size() + 1;
    std::multiset<uint8_t> data_before_mutation(data.begin(), data.end());
    ASSERT_FALSE(mutator::InsertByte(data, /* max_size = */ 1));
    ASSERT_TRUE(mutator::InsertByte(data, expected_current_size));
    ASSERT_TRUE(data.size() == expected_current_size);
    std::multiset<uint8_t> data_after_mutation(data.begin(), data.end());
    EXPECT_TRUE(std::includes(
        data_after_mutation.begin(), data_after_mutation.end(),
        data_before_mutation.begin(), data_before_mutation.end()));
  }
}

TEST(Mutator, TestShuffleBytes) {
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<uint8_t> data_before_mutation = data;
  bool data_changed = false;
  for (int i = 0; i < 100; ++i) {
    srand(i);
    size_t expected_current_size = data.size();
    std::multiset<uint8_t> data_before_mutation_set(data.begin(), data.end());
    ASSERT_FALSE(mutator::ShuffleBytes(data, /* max_size = */ 1));
    ASSERT_TRUE(mutator::ShuffleBytes(data, expected_current_size));
    ASSERT_TRUE(data.size() == expected_current_size);
    std::multiset<uint8_t> data_after_mutation_set(data.begin(), data.end());
    ASSERT_TRUE(data_before_mutation_set == data_after_mutation_set);
    // Check for at least one change throughout all iterations.
    data_changed = data_changed || (data != data_before_mutation);
  }
  EXPECT_TRUE(data_changed);
}

TEST(Mutator, TestMutate) {
  std::vector<uint8_t> data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<uint8_t> data_before_mutation = data;
  ASSERT_TRUE(
      mutator::Mutate(data, data.size(), /* max_mutation_degree = */ 0));
  EXPECT_EQ(data, data_before_mutation);
  for (int i = 1; i < 100; ++i) {
    srand(i);
    size_t expected_min_current_size =
        std::max(0, (int)data_before_mutation.size() - i);
    size_t expected_max_current_size = data_before_mutation.size() + i;
    data = data_before_mutation;
    ASSERT_TRUE(mutator::Mutate(data, expected_max_current_size,
                                /* max_mutation_degree = */ i));
    // Expected data size range in [expected_min_current_size,
    // expected_max_current_size].
    ASSERT_TRUE(expected_min_current_size <= data.size() &&
                data.size() <= expected_max_current_size);
    // Check for reproducibility.
    srand(i);
    std::vector<uint8_t> expected_mutation = data;
    data = data_before_mutation;
    ASSERT_TRUE(mutator::Mutate(data, expected_max_current_size,
                                /* max_mutation_degree = */ i));
    EXPECT_EQ(data, expected_mutation);
  }
}

}  // namespace
}  // namespace mutator
}  // namespace fido2_tests

