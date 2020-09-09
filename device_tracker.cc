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

#include <filesystem>
#include <fstream>
#include <iostream>

#include "parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace {
constexpr std::string_view kRelativeDir = "results/";
constexpr std::string_view kFileName = "NEW_TEST";
constexpr std::string_view kFileType = ".md";

// Creates a directory for results files and returns the path. Just return
// the path if that directory already exists. Fails if the directory wasn't
// created successfully.
std::string CreateSaveFileDirectory() {
  std::string results_dir = std::string(kRelativeDir);
  if (const char* env_dir = std::getenv("BUILD_WORKSPACE_DIRECTORY")) {
    results_dir = absl::StrCat(env_dir, "/", results_dir);
  }
  std::filesystem::create_directory(results_dir);
  return results_dir;
}

// If elements is not empty, prints header and elements in separate lines.
void PrintStringVector(absl::string_view header,
                       absl::Span<const std::string> elements,
                       std::ofstream& output) {
  if (elements.empty()) {
    return;
  }
  output << "\n### " << header << ":\n";
  for (const std::string& element : elements) {
    output << "* " << element << "\n";
  }
}

void PrintSuccessMessage(const std::string& message) {
  std::cout << "\x1b[0;32m" << message << "\x1b[0m" << std::endl;
}

void PrintWarningMessage(const std::string& message) {
  std::cout << "\x1b[0;33m" << message << "\x1b[0m" << std::endl;
}

void PrintFailMessage(const std::string& message) {
  std::cout << "\x1b[0;31m" << message << "\x1b[0m" << std::endl;
}

}  // namespace

DeviceTracker::DeviceTracker()
    : key_checker_(std::vector<std::vector<uint8_t>>()),
      product_name_(kFileName) {}

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

  absl::flat_hash_set<std::string> mutable_options = {"clientPin", "uv",
                                                      "bioEnroll"};
  for (const auto& options_iter : options) {
    if (options_iter.first.is_string() && options_iter.second.is_bool()) {
      bool is_mutable =
          mutable_options.contains(options_iter.first.GetString());
      if (is_mutable || options_iter.second.GetBool()) {
        options_.insert(options_iter.first.GetString());
      }
    }
  }
}

void DeviceTracker::SetProductName(const std::string& product_name) {
  product_name_ = product_name;
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

void DeviceTracker::CheckAndReport(bool condition,
                                   const std::string& test_name) {
  if (condition) {
    PrintSuccessMessage(absl::StrCat("Test successful: ", test_name));
    successful_tests_.push_back(test_name);
  } else {
    PrintFailMessage(absl::StrCat("Failed test: ", test_name));
    failed_tests_.push_back(test_name);
  }
}

void DeviceTracker::CheckAndReport(
    const absl::variant<cbor::Value, Status>& returned_variant,
    const std::string& test_name) {
  Status returned_status = Status::kErrNone;
  if (absl::holds_alternative<Status>(returned_variant)) {
    returned_status = absl::get<Status>(returned_variant);
  }
  CheckAndReport(Status::kErrNone, returned_status, test_name);
}

void DeviceTracker::CheckAndReport(Status expected_status,
                                   Status returned_status,
                                   const std::string& test_name) {
  if ((expected_status == Status::kErrNone) ==
      (returned_status == Status::kErrNone)) {
    if (expected_status == returned_status) {
      PrintSuccessMessage(absl::StrCat("Test successful: ", test_name,
                                       " - returned status code `",
                                       StatusToString(returned_status), "`"));
      successful_tests_.push_back(test_name);
    } else {
      PrintWarningMessage(absl::StrCat(
          "Test successful with unexpected error code: ", test_name,
          " - expected `", StatusToString(expected_status), "`, got `",
          StatusToString(returned_status), "`"));
      AddProblem(absl::StrCat("Unexpected error code: expected `",
                              StatusToString(expected_status), "`, got `",
                              StatusToString(returned_status), "`"));
    }
  } else {
    std::string fail_message =
        absl::StrCat("Failed test: ", test_name, " - expected `",
                     StatusToString(expected_status), "`, got `",
                     StatusToString(returned_status), "`");
    PrintFailMessage(fail_message);
    failed_tests_.push_back(fail_message);
  }
}

KeyChecker* DeviceTracker::GetKeyChecker() { return &key_checker_; }

CounterChecker* DeviceTracker::GetCounterChecker() { return &counter_checker_; }

void DeviceTracker::ReportFindings() const {
  counter_checker_.ReportFindings();
  std::cout << std::endl;
  for (const std::string& observation : observations_) {
    std::cout << observation << "\n";
  }
  std::cout << std::endl;
  for (const std::string& problem : problems_) {
    PrintWarningMessage(problem);
  }
  std::cout << std::endl;
  for (const std::string& test : failed_tests_) {
    PrintFailMessage(test);
  }
  int successful_test_count = successful_tests_.size();
  int failed_test_count = failed_tests_.size();
  int test_count = successful_test_count + failed_test_count;
  std::cout << "Passed " << successful_test_count << " out of " << test_count
            << " tests." << std::endl;
}

void DeviceTracker::SaveResultsToFile() {
  std::filesystem::path results_path =
      absl::StrCat(CreateSaveFileDirectory(), product_name_, kFileType);
  std::ofstream results_file;
  results_file.open(results_path);
  CHECK(results_file.is_open()) << "Unable to open file: " << results_path;

  results_file << "## Results for " << product_name_ << "\n\n";
  int successful_test_count = successful_tests_.size();
  int failed_test_count = failed_tests_.size();
  int test_count = successful_test_count + failed_test_count;
  results_file << "Passed " << successful_test_count << " out of " << test_count
               << " tests.\n";
  PrintStringVector("Failed tests", failed_tests_, results_file);
  PrintStringVector("Reported problems", problems_, results_file);
  PrintStringVector("Reported observations", observations_, results_file);

  counter_checker_.ReportFindings();
}

}  // namespace fido2_tests
