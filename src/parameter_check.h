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

#ifndef PARAMETER_CHECK_H_
#define PARAMETER_CHECK_H_

#include <unordered_set>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

namespace fido2_tests {

// This is a trivial hash used in the hashmap below.
struct ByteVectorHash {
  size_t operator()(const std::vector<uint8_t>& v) const {
    std::hash<uint8_t> hasher;
    std::size_t seed = 0;
    for (int i : v) {
      seed ^= hasher(i);
    }
    return seed;
  }
};

// Tracks used key material for signs of reuse. Reuse of key material is a
// sign for bad RNG and hints at a critical security vulnerability. Any finding
// terminates the execution.
class KeyChecker {
 public:
  explicit KeyChecker(const std::vector<std::vector<uint8_t>>& common_keys);
  void CheckKey(const std::vector<uint8_t>& key);

 private:
  absl::flat_hash_set<std::vector<uint8_t>, ByteVectorHash> key_set_;
};

// Investigates the signature counter. Counters should be strictly increasing.
// Additionally, the class tries to infer the type of signature counter.
// Options are:
// - always zero (discouraged by the specification, flash friendly)
// - global counters (RPs see increments > 1)
// - individual counters (privacy friendly)
class CounterChecker {
 public:
  CounterChecker();
  void RegisterCounter(const std::vector<uint8_t>& id, uint32_t start_value);
  void CheckCounter(const std::vector<uint8_t>& id, uint32_t value);
  std::string_view ReportFindings() const;

 private:
  absl::flat_hash_map<std::vector<uint8_t>, uint32_t, ByteVectorHash>
      counter_map_;
  bool could_be_global_;
  bool could_be_individual_;
  bool could_be_zero_;
};
}  // namespace fido2_tests

#endif  // PARAMETER_CHECK_H_

