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

#include "device_tracker.h"

#include <iostream>

#include "parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

DeviceTracker::DeviceTracker()
    : key_checker_(std::vector<std::vector<uint8_t>>()) {}

void DeviceTracker::Initialize(const cbor::Value::ArrayValue& versions,
                               const cbor::Value::ArrayValue& extensions,
                               const cbor::Value::MapValue& options) {
  if (is_initialized_) {
    return;
  }
  is_initialized_ = true;

  for (const auto& versions_iter : versions) {
    if (versions_iter.is_string()) {
      versions_.insert(versions_iter.GetString());
    }
  }

  for (const auto& extensions_iter : extensions) {
    if (extensions_iter.is_string()) {
      extensions_.insert(extensions_iter.GetString());
    }
  }

  absl::flat_hash_set<std::string> mutable_options =
      {"clientPin", "uv", "bioEnroll"};
  for (const auto& options_iter : options) {
    if (options_iter.first.is_string() && options_iter.second.is_bool()) {
      bool is_mutable = mutable_options.contains(
          options_iter.first.GetString());
      if (is_mutable || options_iter.second.GetBool()) {
        options_.insert(options_iter.first.GetString());
      }
    }
  }
}

void DeviceTracker::AddObservation(const std::string& observation) {
  if (std::find(observations_.begin(), observations_.end(), observation) ==
      observations_.end()) {
    observations_.push_back(observation);
  }
}

void DeviceTracker::AddProblem(const std::string& problem) {
  if (std::find(problems_.begin(), problems_.end(), problem) ==
      problems_.end()) {
    problems_.push_back(problem);
  }
}

KeyChecker* DeviceTracker::GetKeyChecker() {
  return &key_checker_;
}

CounterChecker* DeviceTracker::GetCounterChecker() {
  return &counter_checker_;
}

void DeviceTracker::ReportFindings() const {
  for (const std::string& observation : observations_) {
    std::cout << observation << "\n";
  }
  std::cout << std::endl;
  for (const std::string& problem : problems_) {
    std::cout << "\x1b[0;33m" << problem << "\x1b[0m"
              << "\n";
  }
  std::cout << std::endl;
  counter_checker_.ReportFindings();
}

}  // namespace fido2_tests

