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

#ifndef DEVICE_TRACKER_H_
#define DEVICE_TRACKER_H_

#include <vector>

#include "absl/container/flat_hash_set.h"
#include "nlohmann/json.hpp"
#include "src/constants.h"
#include "src/device_interface.h"
#include "src/parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// Contains all information that is logged in a test.
struct TestResult {
  nlohmann::json ToJson() const;

  std::string test_id;
  std::string test_description;
  std::optional<std::string> error_message;
  std::vector<std::string> observations;
  std::vector<std::string> tags;
};

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
  // GetInfo call. The passed in info_map must be a valid GetInfo response.
  void Initialize(const cbor::Value::MapValue& info_map);
  // Returns if the device supports the version. Will always return false if not
  // initialized.
  bool HasVersion(std::string_view version_name) const;
  // Returns if the device supports the extension. Will always return false if
  // not initialized.
  bool HasExtension(std::string_view extension_name) const;
  // Returns if the device supports the option. Will always return false if not
  // initialized.
  bool HasOption(std::string_view option_name) const;
  // Returns the minimum PIN length as advertized in GetInfo.
  size_t GetMinPinLength() const;
  // Returns if the device sets the wink capability in its response to Init.
  // Must be set through SetCapabilities, or returns false.
  bool HasWinkCapability() const;
  // Returns if the device sets the cbor capability in its response to Init.
  // Must be set through SetCapabilities or returns false.
  bool HasCborCapability() const;
  // Stores the capability responses to be included in the report.
  void SetCapabilities(bool wink, bool cbor, bool msg);
  // Setter for the device identifiers, for writing to the result file. Must be
  // called at least once.
  void SetDeviceIdentifiers(DeviceIdentifiers device_identifiers);
  // Setter for the AAGUID, which is reported as a device identifier.
  void SetAaguid(std::string_view aaguid);
  // The next time a touch prompt is received, it should be ignored. Call
  // IsTouchPromptIgnored to consume.
  void IgnoreNextTouchPrompt();
  // Returns true if IgnoreNextTouchPrompt was called before, and then false
  // until IgnoreNextTouchPrompt is called again.
  bool IsTouchPromptIgnored();
  // Adds a string to the list of observations. Duplicates are ignored.
  // Observations are logged with the next finished test.
  void AddObservation(const std::string& observation);
  // Asserts a general condition, exits on failure. Prints all results collected
  // so far and saves them into a file.
  void AssertCondition(bool condition, std::string_view message);
  // As above, but asserts that the Status is kErrNone.
  void AssertStatus(Status status, std::string_view message);
  // As above, but asserts the success of an executed command.
  void AssertResponse(
      const absl::variant<cbor::Value, Status>& returned_variant,
      std::string_view message);
  // Returns whether the status is a success.
  bool CheckStatus(Status status);
  // Returns if the expected and returned status are both an error or both not
  // an error. If both are different errors, report an observation.
  bool CheckStatus(Status expected_status, Status returned_status);
  // Returns whether the response is a value or the success status.
  bool CheckStatus(const absl::variant<cbor::Value, Status>& returned_variant);
  // Logs a test and its result.
  void LogTest(std::string test_id, std::string test_description,
               std::optional<std::string> error_message,
               std::vector<std::string> tags);
  // Returns a reference to the KeyChecker instance.
  KeyChecker* GetKeyChecker();
  // Returns a reference to the CounterChecker instance.
  CounterChecker* GetCounterChecker();
  // Prints a report including all information from the CounterChecker, logged
  // observations, problems and tests.
  void ReportFindings() const;
  // Generates a JSON object with test results.
  nlohmann::json GenerateResultsJson(std::string_view commit_hash,
                                     std::string_view time_string) const;
  // Saves the results to a JSON file. Creates a "results" directory, if
  // necessary. The file name will be derived from the product name as listed
  // through HID, or a default if none is found. Overwrites existing files of
  // the same name. The commit is stamped into the binary and read here.
  void SaveResultsToFile(std::string_view results_dir = "results/") const;

 private:
  KeyChecker key_checker_;
  CounterChecker counter_checker_;
  // You need to call SetDeviceIdentifiers to initialize.
  DeviceIdentifiers device_identifiers_;
  std::string aaguid_;
  bool ignores_touch_prompt_ = false;
  // We want the observations and tests to be listed in order of appearance.
  std::vector<std::string> observations_;
  std::vector<TestResult> tests_;
  absl::flat_hash_set<std::string> versions_;
  absl::flat_hash_set<std::string> extensions_;
  // Some options have three states, unsupported, inactive and active.
  // We only care about being supported in general, and activate as necessary.
  // Also, options that default to true are always initialized.
  absl::flat_hash_set<std::string> options_;
  size_t min_pin_length_ = 4;
  bool is_initialized_ = false;
  bool has_wink_capability_ = false;
  bool has_cbor_capability_ = false;
  bool has_msg_capability_ = false;
};

}  // namespace fido2_tests

#endif  // DEVICE_TRACKER_H_

