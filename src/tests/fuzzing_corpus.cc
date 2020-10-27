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

#include "src/constants.h"
#include "src/corpus_controller.h"

namespace fido2_tests {
namespace {
// Runs all files of the given type, which should be stored in a folder inside
// the corpus under a naming convention (see src/test_input_controller.h). When
// the monitor detects a crash, stops execution.
std::optional<std::string> Execute(fido2_tests::InputType input_type,
                                   DeviceInterface* device,
                                   fido2_tests::Monitor* monitor,
                                   const std::string_view& base_corpus_path) {
  fido2_tests::CorpusIterator corpus_iterator(input_type, base_corpus_path);
  int passed_test_files = 0;
  // Prepares the monitor for this test cycle.
  CHECK(monitor->Prepare()) << "Monitor preparation failed!";
  while (corpus_iterator.HasNextInput()) {
    auto [input_data, input_path] = corpus_iterator.GetNextInput();
    // std::cout << "Running file " << input_path << std::endl;
    fido2_tests::SendInput(device, input_type, input_data);
    if (monitor->DeviceCrashed()) {
      monitor->PrintCrashReport();
      std::string save_path = monitor->SaveCrashFile(input_type, input_path);
      return absl::StrCat("Saved crash input to ", save_path,
                          ". Ran a total of ", passed_test_files, " files.");
    }
    ++passed_test_files;
  }
  return std::nullopt;
}

}  // namespace

MakeCredentialCorpusTest::MakeCredentialCorpusTest(
    fido2_tests::Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("make_credential_corpus",
               "Tests the corpus of ctap make credential commands.",
               {.has_pin = false}, {Tag::kClientPin}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> MakeCredentialCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(
      fido2_tests::InputType::kCborMakeCredentialParameter, device, monitor_,
      base_corpus_path_);
}

GetAssertionCorpusTest::GetAssertionCorpusTest(
    fido2_tests::Monitor* monitor, const std::string_view& base_corpus_path)
    : BaseTest("get_assertion_corpus",
               "Tests the corpus of ctap get assertion commands.",
               {.has_pin = false}, {Tag::kClientPin}),
      monitor_(monitor),
      base_corpus_path_(base_corpus_path) {}

std::optional<std::string> GetAssertionCorpusTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return ::fido2_tests::Execute(
      fido2_tests::InputType::kCborGetAssertionParameter, device, monitor_,
      base_corpus_path_);
}

}  // namespace fido2_tests
