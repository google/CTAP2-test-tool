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

#include "src/tests/fuzzing_corpus.h"

#include <iostream>

#include "absl/strings/str_split.h"
#include "src/constants.h"
#include "src/corpus_controller.h"

namespace fido2_tests {
namespace {

// Prints a line stating the file being run, rewriting the last line of output.
void PrintRunningFile(std::string_view file_name) {
  // \033[A moves the cursor up 1 line, \33[2K erase the line and \r brings the
  // cursor to the beginning of line.
  std::cout << "\033[A\33[2K\rRunning file " << file_name << std::endl;
}

// Runs all files of the given type, which should be stored in a folder inside
// the corpus under a naming convention (see src/test_input_controller.h). When
// the monitor detects a crash, stops execution.
std::optional<std::string> Execute(DeviceInterface* device,
                                   CommandState* command_state,
                                   Monitor* monitor, InputType input_type,
                                   const std::string_view& base_corpus_path) {
  CorpusIterator corpus_iterator(input_type, base_corpus_path);
  int passed_test_files = 0;
  std::cout << "\n|--- Processing corpus "
            << InputTypeToDirectoryName(input_type) << " ---|\n\n\n";
  while (corpus_iterator.HasNextInput()) {
    auto [input_data, input_path] = corpus_iterator.GetNextInput();
    std::string input_name =
        static_cast<std::vector<std::string>>(absl::StrSplit(input_path, '/'))
            .back();
    PrintRunningFile(input_name);
    SendInput(device, input_type, input_data);
    if (monitor->DeviceCrashed(command_state)) {
      monitor->PrintCrashReport();
      std::string save_path = monitor->SaveCrashFile(input_type, input_path);
      return absl::StrCat("Saved crash input to ", save_path,
                          ". Ran a total of ", passed_test_files, " files.");
    }
    ++passed_test_files;
  }
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
               "Tests the corpus of ctap make credential commands.",
               {.has_pin = false}, {Tag::kClientPin}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> MakeCredentialCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(device, command_state, monitor_,
                                InputType::kCborMakeCredentialParameter,
                                base_corpus_path_);
}

void MakeCredentialCorpusTest::Setup(CommandState* command_state) const {
  BaseTest::Setup(command_state);
  ::fido2_tests::Setup(command_state, monitor_);
}

GetAssertionCorpusTest::GetAssertionCorpusTest(
    Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("get_assertion_corpus",
               "Tests the corpus of ctap get assertion commands.",
               {.has_pin = false}, {Tag::kClientPin}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> GetAssertionCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(device, command_state, monitor_,
                                InputType::kCborGetAssertionParameter,
                                base_corpus_path_);
}

void GetAssertionCorpusTest::Setup(CommandState* command_state) const {
  BaseTest::Setup(command_state);
  ::fido2_tests::Setup(command_state, monitor_);
}

}  // namespace fido2_tests

