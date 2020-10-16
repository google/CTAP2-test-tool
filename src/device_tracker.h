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
#include "nlohmann/json.hpp"
#include "src/constants.h"
#include "src/parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// Tracks all interesting capabilities and findings during test execution. This
// includes all global state, i.e. properties that can not be changed through
// CTAP commands. You can manually add observations or problems. When executing
// a command, you can also call one of the variants of CheckAndReport to
// evaluate it. To summarize the findings, run ReportFindings. Initialization
// requires the output of a GetInfo command.
class DeviceTracker {
 public:
  // Generates a new KeyChecker and CounterChecker. Version specific information
  // is not available until calling Initialize. You can always log findings.
  DeviceTracker();
  // Writes information about device capabilities. Call this function during a
  // GetInfo call.
  void Initialize(const cbor::Value::ArrayValue& versions,
                  const cbor::Value::ArrayValue& extensions,
                  const cbor::Value::MapValue& options);
  // Returns if the device supports the version. Will always return false if not
  // initialized.
  bool HasVersion(std::string_view version_name);
  // Returns if the device supports the extension. Will always return false if
  // not initialized.
  bool HasExtension(std::string_view extension_name);
  // Returns if the device supports the option. Will always return false if not
  // initialized.
  bool HasOption(std::string_view option_name);
  // Setter for the product_name, which is used as a results file name.
  void SetProductName(std::string_view product_name);
  // Adds a string to the list of observations. Duplicates are ignored. Use this
  // function for merely informational comments.
  void AddObservation(const std::string& observation);
  // Adds a string to the list of problems. Duplicates are ignored. Problems
  // are highlighted more prominently during a report. Use this if you suspect
  // the finding to be potentially problematic.
  void AddProblem(const std::string& problem);
  // Asserts a general condition, exits on failure. Prints all results collected
  // so far and saves them into a file.
  void AssertCondition(bool condition, std::string_view message);
  // As above, but asserts that the Status is kErrNone.
  void AssertStatus(Status status, std::string_view message);
  // As above, but asserts the success of an executed command.
  void AssertResponse(
      const absl::variant<cbor::Value, Status>& returned_variant,
      std::string_view message);
  // Checks a general condition, reporting the result and writing statistics.
  void CheckAndReport(bool condition, const std::string& test_name);
  // As above, but checks specifically whether the variant is a CBOR value.
  void CheckAndReport(
      const absl::variant<cbor::Value, Status>& returned_variant,
      const std::string& test_name);
  // As above, but checks specifically if the expected and returned status are
  // both an error or both not an error. If both are different errors, the test
  // counts as passed, but the report contains a warning.
  void CheckAndReport(Status expected_status, Status returned_status,
                      const std::string& test_name);
  // Returns a reference to the KeyChecker instance.
  KeyChecker* GetKeyChecker();
  // Returns a reference to the CounterChecker instance.
  CounterChecker* GetCounterChecker();
  // Prints a report including all information from the CounterChecker, logged
  // observations, problems and tests.
  void ReportFindings() const;
  // Generates a JSON object with test results.
  nlohmann::json GenerateResultsJson();
  // Saves the results to a JSON file. Creates a "results" directory, if
  // necessary. The file name will be derived from the product name as listed
  // through HID, or a default if none is found. Overwrites existing files of
  // the same name.
  void SaveResultsToFile();

 private:
  KeyChecker key_checker_;
  CounterChecker counter_checker_;
  std::string product_name_;
  // We want the observations, problems and tests to be listed in order of
  // appearance.
  std::vector<std::string> observations_;
  std::vector<std::string> problems_;
  std::vector<std::string> successful_tests_;
  std::vector<std::string> failed_tests_;
  absl::flat_hash_set<std::string> versions_;
  absl::flat_hash_set<std::string> extensions_;
  // Some options have three states, unsupported, inactive and active.
  // We only care about being supported in general, and activate as necessary.
  absl::flat_hash_set<std::string> options_;
  bool is_initialized_;
};

}  // namespace fido2_tests

#endif  // DEVICE_TRACKER_H_
