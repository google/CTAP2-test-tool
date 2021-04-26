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

#include "src/tests/fuzzing_corpus.h"

#include <iostream>

#include "absl/strings/str_split.h"
#include "src/constants.h"
#include "src/fuzzing/corpus_controller.h"

namespace fido2_tests {
namespace {

// Default number of retries.
constexpr int kRetries = 3;

// Prints a line stating the file being run, rewriting the last line of output.
void PrintRunningFile(std::string_view file_name, size_t last_file_name_len) {
  // Clean last line output in case the current line to be printed is shorter.
  std::cout << "\r             " << std::string(last_file_name_len + 1, ' ');
  std::cout << "\rRunning file " << file_name << ". " << std::flush;
}

// Runs all files of the given type, which should be stored in a folder inside
// the corpus under a naming convention (see src/test_input_controller.h). When
// the monitor detects a crash, stops execution.
std::optional<std::string> Execute(DeviceInterface* device,
                                   DeviceTracker* device_tracker,
                                   CommandState* command_state,
                                   Monitor* monitor,
                                   fuzzing_helpers::InputType input_type,
                                   const std::string_view& base_corpus_path) {
  CorpusController corpus_controller(input_type, base_corpus_path);
  int passed_test_files = 0;
  size_t last_file_name_len = 0;
  std::cout << "\n|--- Processing corpus "
            << InputTypeToDirectoryName(input_type) << " ---|\n\n";
  while (corpus_controller.HasNextInput()) {
    auto [input_data, input_name] = corpus_controller.GetNextInput();
    PrintRunningFile(input_name, last_file_name_len);
    SendInput(device, input_type, input_data);
    auto [device_crashed, observations] =
        monitor->DeviceCrashed(command_state, kRetries);
    for (const std::string& observation : observations) {
      device_tracker->AddObservation(
          absl::StrCat("In file ", input_name, " ", observation));
    }
    if (device_crashed) {
      monitor->PrintCrashReport();
      std::string save_path =
          monitor->SaveCrashFile(input_type, input_data, input_name);
      return absl::StrCat("Saved crash input to ", save_path,
                          ". Ran a total of ", passed_test_files, " files.");
    }
    ++passed_test_files;
    last_file_name_len = input_name.size();
  }
  std::cout << std::endl;
  return std::nullopt;
}

void Setup(CommandState* command_state, Monitor* monitor) {
  // Prepares the monitor for this test cycle.
  CHECK(monitor->Prepare(command_state)) << "Monitor preparation failed!";
}

}  // namespace

MakeCredentialCorpusTest::MakeCredentialCorpusTest(
    Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("make_credential_corpus",
               "Tests the corpus of CTAP MakeCredential commands.",
               {.has_pin = false}, {Tag::kFuzzing}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> MakeCredentialCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(
      device, device_tracker, command_state, monitor_,
      fuzzing_helpers::InputType::kCborMakeCredentialParameter,
      base_corpus_path_);
}

void MakeCredentialCorpusTest::Setup(CommandState* command_state) const {
  BaseTest::Setup(command_state);
  ::fido2_tests::Setup(command_state, monitor_);
}

GetAssertionCorpusTest::GetAssertionCorpusTest(
    Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("get_assertion_corpus",
               "Tests the corpus of CTAP GetAssertion commands.",
               {.has_pin = false}, {Tag::kFuzzing}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> GetAssertionCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(
      device, device_tracker, command_state, monitor_,
      fuzzing_helpers::InputType::kCborGetAssertionParameter,
      base_corpus_path_);
}

void GetAssertionCorpusTest::Setup(CommandState* command_state) const {
  BaseTest::Setup(command_state);
  ::fido2_tests::Setup(command_state, monitor_);
}

ClientPinCorpusTest::ClientPinCorpusTest(
    Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("client_pin_corpus",
               "Tests the corpus of CTAP ClientPIN commands.",
               {.has_pin = false}, {Tag::kFuzzing}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> ClientPinCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(
      device, device_tracker, command_state, monitor_,
      fuzzing_helpers::InputType::kCborClientPinParameter, base_corpus_path_);
}

void ClientPinCorpusTest::Setup(CommandState* command_state) const {
  BaseTest::Setup(command_state);
  ::fido2_tests::Setup(command_state, monitor_);
}

}  // namespace fido2_tests

