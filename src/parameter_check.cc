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

#include "src/parameter_check.h"

#include <algorithm>

#include "glog/logging.h"

namespace fido2_tests {

KeyChecker::KeyChecker(const std::vector<std::vector<uint8_t>>& common_keys)
    : key_set_(absl::flat_hash_set<std::vector<uint8_t>, ByteVectorHash>(
          common_keys.begin(), common_keys.end())) {}

void KeyChecker::CheckKey(const std::vector<uint8_t>& key) {
  CHECK(key_set_.find(key) == key_set_.end())
      << "key is either a duplicate or too common";
  key_set_.insert(key);
}

CounterChecker::CounterChecker()
    : counter_map_(absl::flat_hash_map<std::vector<uint8_t>, uint32_t,
                                       ByteVectorHash>()),
      could_be_global_(true),
      could_be_individual_(true),
      could_be_zero_(true) {}

void CounterChecker::RegisterCounter(const std::vector<uint8_t>& id,
                                     uint32_t start_value) {
  CHECK(counter_map_.find(id) == counter_map_.end())
      << "trying to register the same counter twice";
  if (start_value != 0) {
    could_be_zero_ = false;
  }
  counter_map_[id] = start_value;
}
void CounterChecker::CheckCounter(const std::vector<uint8_t>& id,
                                  uint32_t value) {
  auto iter = counter_map_.find(id);
  CHECK(iter != counter_map_.end()) << "counter is not registered yet";
  const uint32_t last_value = iter->second;
  if (value <= last_value) {
    could_be_global_ = false;
  }
  if (value != last_value + 1) {
    could_be_individual_ = false;
  }
  if (value != 0) {
    could_be_zero_ = false;
  }
  counter_map_[id] = value;
}

std::string_view CounterChecker::ReportFindings() const {
  if (could_be_zero_) {
    return "All counters were constant zero.";
  } else {
    if (could_be_individual_) {
      return "All counters were strictly incremented by 1.";
    } else {
      if (could_be_global_) {
        return "All counters were strictly increasing, but not necessarily "
               "incremented by 1.";
      } else {
        return "There were counters that were not strictly increasing.";
      }
    }
  }
}

}  // namespace fido2_tests

