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

#ifndef FUZZING_MUTATOR_H_
#define FUZZING_MUTATOR_H_

#include <cstdint>
#include <vector>

namespace fido2_tests {
namespace mutator {

enum MutationOperation {
  kEraseByte,
  kInsertByte,
  kShuffleBytes,
};
// Erases one byte from a random position of the given data (in-out parameter).
bool EraseByte(std::vector<uint8_t> &data, size_t max_size);
// Inserts a random byte in a random position of the given data (in-out
// parameter).
bool InsertByte(std::vector<uint8_t> &data, size_t max_size);
// Rearranges a random section of the given data (in-out parameter).
bool ShuffleBytes(std::vector<uint8_t> &data, size_t max_size);
// Applies a random degree (up to max_mutation_degree) of basic mutation
// operations to the given data (in-out parameter).
bool Mutate(std::vector<uint8_t> &data, size_t max_size,
            int max_mutation_degree);

}  // namespace mutator
}  // namespace fido2_tests

#endif  // FUZZING_MUTATOR_H_

