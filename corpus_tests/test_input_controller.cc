// Copyright 2019 Google LLC
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

#include "corpus_tests/test_input_controller.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "absl/strings/str_split.h"

namespace corpus_tests {

TestInputController::TestInputController(std::string corpus_path)
    : TestInputController(/* fuzzing = */ false, corpus_path) {}

TestInputController::TestInputController(bool fuzzing, std::string corpus_path)
    : fuzzing_(fuzzing), current_input_(corpus_path) {}

bool TestInputController::InputAvailable() {
  if (!fuzzing_) {
    std::filesystem::directory_iterator end;
    return current_input_ != end;
  }
  return true;  // In fuzzing case, there is always input available.
}

void TestInputController::GetNextInput() { ++current_input_; }

fido2_tests::Status TestInputController::RunCurrentInput(
    fido2_tests::DeviceInterface* device) {
  // Corpus testing.
  if (!fuzzing_) {
    std::ifstream file(current_input_->path(), std::ios::in | std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());

    std::vector<absl::string_view> path_splits =
        absl::StrSplit(current_input_->path().string(), '/');
    std::vector<absl::string_view> current_input_name =
        absl::StrSplit(path_splits.back(), '_');
    if (current_input_name.size() > 0 && current_input_name[0] == "cbor") {
      std::vector<uint8_t> response;
      // TODO(mingxguo): Complete cases. Replace default command with
      // a random choice?
      fido2_tests::Command command =
          fido2_tests::Command::kAuthenticatorGetInfo;
      if (current_input_name[1] == "makecredential") {
        command = fido2_tests::Command::kAuthenticatorMakeCredential;
      } else if (current_input_name[1] == "getassertion") {
        command = fido2_tests::Command::kAuthenticatorGetAssertion;
      }
      return device->ExchangeCbor(command, data, false, &response);
    }
    // TODO(mingxguo): other cases.
  }
  // TODO(mingxguo): Fuzzing case
}

}  // namespace corpus_tests