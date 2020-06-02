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

#ifndef DEVICE_TRACKER_H_
#define DEVICE_TRACKER_H_

#include <vector>

#include "absl/container/flat_hash_set.h"
#include "parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

class DeviceTracker {
 public:
  DeviceTracker();
  void Initialize(const cbor::Value::ArrayValue& versions,
                  const cbor::Value::ArrayValue& extensions,
                  const cbor::Value::MapValue& options);
  void AddObservation(const std::string& observation);
  void AddProblem(const std::string& problem);
  KeyChecker* GetKeyChecker();
  CounterChecker* GetCounterChecker();
  void ReportFindings();

 private:
  KeyChecker key_checker_;
  CounterChecker counter_checker_;
  // We want the observations and problems to be listed in order of appearance.
  std::vector<std::string> observations_;
  std::vector<std::string> problems_;
  absl::flat_hash_set<std::string> versions_;
  absl::flat_hash_set<std::string> extensions_;
  // Some options have three states, unsupported, inactive and active.
  // We only care about being supported in general, and activate as necessary.
  absl::flat_hash_set<std::string> options_;
  bool is_initialized_;
};

}  // namespace fido2_tests

#endif  // DEVICE_TRACKER_H_

