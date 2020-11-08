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

#ifndef MUTATOR_H_
#define MUTATOR_H_

#include <vector>

namespace fido2_tests {

class Mutator {
 public:
  enum MutationOperation {
    kEraseByte,
    kInsertByte,
    kShuffleBytes,
  };
  Mutator(int max_mutation_degree = 10, int seed = time(NULL));
  bool EraseByte(std::vector<uint8_t> &data, size_t max_size);
  bool InsertByte(std::vector<uint8_t> &data, size_t max_size);
  bool ShuffleBytes(std::vector<uint8_t> &data, size_t max_size);

  bool Mutate(std::vector<uint8_t> &data, size_t max_size);

 private:
  int max_mutation_degree_;
};

}  // namespace fido2_tests

#endif  // MUTATOR_H_
