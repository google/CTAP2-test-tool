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

#include "src/device_tracker.h"

#include <filesystem>
#include <fstream>
#include <iostream>

#include "src/parameter_check.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace {
constexpr std::string_view kRelativeDir = "results/";
constexpr std::string_view kFileName = "NEW_TEST";
constexpr std::string_view kFileType = ".json";

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

void PrintSuccessMessage(std::string_view message) {
  std::cout << "\x1b[0;32m" << message << "\x1b[0m" << std::endl;
}

void PrintWarningMessage(std::string_view message) {
  std::cout << "\x1b[0;33m" << message << "\x1b[0m" << std::endl;
}

void PrintFailMessage(std::string_view message) {
  std::cout << "\x1b[0;31m" << message << "\x1b[0m" << std::endl;
}

}  // namespace

DeviceTracker::DeviceTracker()
    : key_checker_(std::vector<std::vector<uint8_t>>()),
      product_name_(kFileName),
      is_initialized_(false) {}

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

bool DeviceTracker::HasVersion(std::string_view version_name) {
  return versions_.contains(version_name);
}

bool DeviceTracker::HasExtension(std::string_view extension_name) {
  return extensions_.contains(extension_name);
}

bool DeviceTracker::HasOption(std::string_view option_name) {
  return options_.contains(option_name);
}

void DeviceTracker::SetProductName(std::string_view product_name) {
  product_name_ = product_name;
}

void DeviceTracker::AddObservation(const std::string& observation) {
  if (std::find(observations_.begin(), observations_.end(), observation) ==
      observations_.end()) {
    observations_.push_back(observation);
  }
}

void DeviceTracker::AddProblem(const std::string& problem) {
  PrintWarningMessage(problem);
  if (std::find(problems_.begin(), problems_.end(), problem) ==
      problems_.end()) {
    problems_.push_back(problem);
  }
}

void DeviceTracker::AssertCondition(bool condition, std::string_view message) {
  ReportFindings();
  SaveResultsToFile();
  CHECK(condition) << "Failed critical test: " << message;
}

void DeviceTracker::AssertStatus(Status status, std::string_view message) {
  AssertCondition(status == Status::kErrNone,
                  absl::StrCat(message, " - returned status code ",
                               StatusToString(status)));
}

void DeviceTracker::AssertResponse(
    const absl::variant<cbor::Value, Status>& returned_variant,
    std::string_view message) {
  Status returned_status = Status::kErrNone;
  if (absl::holds_alternative<Status>(returned_variant)) {
    returned_status = absl::get<Status>(returned_variant);
  }
  AssertStatus(returned_status, message);
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
    PrintSuccessMessage(absl::StrCat("Test successful: ", test_name));
    successful_tests_.push_back(test_name);
    if (expected_status != returned_status) {
      AddProblem(absl::StrCat("Expected error code ",
                              StatusToString(expected_status), ", got ",
                              StatusToString(returned_status)));
    }
  } else {
    std::string fail_message =
        absl::StrCat(test_name, " - expected ", StatusToString(expected_status),
                     ", got ", StatusToString(returned_status));
    PrintFailMessage(absl::StrCat("Failed test: ", fail_message));
    failed_tests_.push_back(fail_message);
  }
}

KeyChecker* DeviceTracker::GetKeyChecker() { return &key_checker_; }

CounterChecker* DeviceTracker::GetCounterChecker() { return &counter_checker_; }

void DeviceTracker::ReportFindings() const {
  std::cout << counter_checker_.ReportFindings() << "\n\n";
  for (std::string_view observation : observations_) {
    std::cout << observation << "\n";
  }
  std::cout << std::endl;
  for (std::string_view problem : problems_) {
    PrintWarningMessage(problem);
  }
  std::cout << std::endl;
  for (std::string_view test : failed_tests_) {
    PrintFailMessage(test);
  }
  int successful_test_count = successful_tests_.size();
  int failed_test_count = failed_tests_.size();
  int test_count = successful_test_count + failed_test_count;
  std::cout << "Passed " << successful_test_count << " out of " << test_count
            << " tests." << std::endl;
}

nlohmann::json DeviceTracker::GenerateResultsJson() {
  int successful_test_count = successful_tests_.size();
  int failed_test_count = failed_tests_.size();
  int test_count = successful_test_count + failed_test_count;

  nlohmann::json results = {
      {"Passed tests", successful_test_count},
      {"Total tests", test_count},
      {"Failed tests", failed_tests_},
      {"Reported problems", problems_},
      {"Reported observations", observations_},
      {"Counter", counter_checker_.ReportFindings()},
  };
  return results;
}

void DeviceTracker::SaveResultsToFile() {
  std::filesystem::path results_path =
      absl::StrCat(CreateSaveFileDirectory(), product_name_, kFileType);
  std::ofstream results_file;
  results_file.open(results_path);
  CHECK(results_file.is_open()) << "Unable to open file: " << results_path;

  results_file << std::setw(2) << GenerateResultsJson() << std::endl;
}

}  // namespace fido2_tests
