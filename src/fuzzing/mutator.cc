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
#include <cstdlib>
#include <iostream>
#include <random>

#include "glog/logging.h"

namespace fido2_tests {
namespace mutator {
namespace {

constexpr int kMutationOperations = 3;

uint8_t RandomByte() { return static_cast<uint8_t>(std::rand() % 256); }

}  // namespace

bool EraseByte(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() <= 1) return false;
  int index = std::rand() % data.size();
  data.erase(data.begin() + index);
  return true;
}

bool InsertByte(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() >= max_size) return false;
  int index = std::rand() % data.size();
  uint8_t elem = RandomByte();
  data.insert(data.begin() + index, elem);
  return true;
}

bool ShuffleBytes(std::vector<uint8_t> &data, size_t max_size) {
  if (data.size() > max_size || data.size() <= 1) return false;
  int shuffle_count = std::rand() % data.size();
  int shuffle_offset = std::rand() % (data.size() - shuffle_count);
  std::shuffle(data.begin() + shuffle_offset,
               data.begin() + shuffle_offset + shuffle_count,
               std::default_random_engine());
  return true;
}

bool Mutate(std::vector<uint8_t> &data, size_t max_size,
            int max_mutation_degree) {
  if (max_mutation_degree < 0) return false;
  if (max_mutation_degree == 0) return true;
  // Mutation degree in range (0, max_mutation_degree]
  int mutation_degree = std::rand() % max_mutation_degree + 1;
  while (mutation_degree--) {
    int op = std::rand() % kMutationOperations;
    switch (static_cast<MutationOperation>(op)) {
      case kEraseByte:
        EraseByte(data, max_size);
        break;
      case kInsertByte:
        InsertByte(data, max_size);
        break;
      case kShuffleBytes:
        ShuffleBytes(data, max_size);
        break;
      default:
        CHECK(false) << "unreachable default - TEST SUITE BUG";
    }
  }
  // For now, mutate always succeeds. If no mutation operation could apply, data
  // remains unmutated.
  return true;
}
}  // namespace mutator
}  // namespace fido2_tests

