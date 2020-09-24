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

void TestInputIterator::FindNextInput() {
  std::filesystem::directory_iterator end;
  while (current_input_ == end) {
    ++current_subdirectory_;
    if (current_subdirectory_ != end && current_subdirectory_->is_directory()) {
      current_input_ = std::filesystem::directory_iterator(
          current_subdirectory_->path().string());
    } else if (current_subdirectory_ == end) {
      // End of iterator.
      break;
    }
  }
}

InputType TestInputIterator::GetInputType() {
  if (current_subdirectory_ != std::filesystem::directory_iterator()) {
    std::vector<absl::string_view> path_splits =
        absl::StrSplit(current_subdirectory_->path().string(), '/');
    std::vector<absl::string_view> current_subdirectory_name =
        absl::StrSplit(path_splits.back(), '_');
    if (current_subdirectory_name.size() > 0 &&
        current_subdirectory_name[0] == "Cbor") {
      if (current_subdirectory_name.size() > 1 &&
          current_subdirectory_name[1] == "MakeCredentialParameters") {
        return InputType::kCborMakeCredentialParameter;
      } else if (current_subdirectory_name.size() > 1 &&
                 current_subdirectory_name[1] == "GetAssertionParameters") {
        return InputType::kCborGetAssertionParameter;
      }
    }
  }
  return InputType::kNotRecognized;
}

TestInputIterator::TestInputIterator(std::string_view corpus_path) {
  current_subdirectory_ = std::filesystem::directory_iterator(corpus_path);
  if (current_subdirectory_ != std::filesystem::directory_iterator() &&
      current_subdirectory_->is_directory()) {
    current_input_ = std::filesystem::directory_iterator(
        current_subdirectory_->path().string());
    FindNextInput();
  }
}

bool TestInputIterator::HasNextInput() {
  return current_input_ != std::filesystem::directory_iterator();
}

InputType TestInputIterator::GetNextInput(std::vector<uint8_t>& input_data) {
  std::ifstream file(current_input_->path(), std::ios::in | std::ios::binary);
  input_data = std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
  InputType input_type = GetInputType();
  ++current_input_;
  FindNextInput();
  return input_type;
}

fido2_tests::Status SendInput(fido2_tests::DeviceInterface* device,
                              InputType input_type,
                              std::vector<uint8_t> const& input) {
  std::vector<uint8_t> response;
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return device->ExchangeCbor(fido2_tests::Command::kAuthenticatorGetInfo,
                                  input, false, &response);
    case InputType::kCborGetAssertionParameter:
      return device->ExchangeCbor(
          fido2_tests::Command::kAuthenticatorGetAssertion, input, false,
          &response);
    default:
      return fido2_tests::Status::kErrOther;
  }
}

}  // namespace corpus_tests