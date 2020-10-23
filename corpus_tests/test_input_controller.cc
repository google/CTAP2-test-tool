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

#include "corpus_tests/test_input_controller.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "absl/strings/str_split.h"
#include "glog/logging.h"

namespace corpus_tests {
namespace {

// Helper function that returns the specific type of cbor parameter inputs.
InputType GetCborInputType(std::vector<absl::string_view> subdirectory_name) {
  if (subdirectory_name.size() > 1 &&
      subdirectory_name[1] == "MakeCredentialParameters") {
    return InputType::kCborMakeCredentialParameter;
  }
  if (subdirectory_name.size() > 1 &&
      subdirectory_name[1] == "GetAssertionParameters") {
    return InputType::kCborGetAssertionParameter;
  }
  // TODO (#27): support more types.
  return InputType::kCborRaw;
}

// Helper function that returns the type of contained inputs based on the
// subdirectory name.
InputType GetInputType(std::string_view subdirectory_name) {
  std::vector<absl::string_view> name_splits =
      absl::StrSplit(subdirectory_name, '_');
  if (name_splits.size() > 0 && name_splits[0] == "Cbor") {
    return GetCborInputType(name_splits);
  }
  // TODO (#27): support more types.
  return InputType::kRawBytes;
}

}  // namespace

void CorpusIterator::UpdateInputPointer() {
  std::filesystem::directory_iterator end;
  while (current_input_ == end) {
    ++current_subdirectory_;
    if (current_subdirectory_ == end) {
      break;
    }
    if (current_subdirectory_->is_directory()) {
      current_input_ = std::filesystem::directory_iterator(
          current_subdirectory_->path().string());
    }
  }
}

CorpusIterator::CorpusIterator(std::string_view corpus_path) {
  current_subdirectory_ = std::filesystem::directory_iterator(corpus_path);
  if (current_subdirectory_ != std::filesystem::directory_iterator() &&
      current_subdirectory_->is_directory()) {
    current_input_ = std::filesystem::directory_iterator(
        current_subdirectory_->path().string());
    UpdateInputPointer();
  }
}

bool CorpusIterator::HasNextInput() {
  return current_input_ != std::filesystem::directory_iterator();
}

std::tuple<InputType, std::vector<uint8_t>, std::string>
CorpusIterator::GetNextInput() {
  std::string input_path = current_input_->path();
  std::ifstream file(current_input_->path(), std::ios::in | std::ios::binary);
  std::vector<uint8_t> input_data = std::vector<uint8_t>(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  std::vector<absl::string_view> path_splits =
      absl::StrSplit(current_subdirectory_->path().string(), '/');
  InputType input_type = GetInputType(path_splits.back());
  ++current_input_;
  UpdateInputPointer();
  return {input_type, input_data, input_path};
}

std::string InputTypeToDirectoryName(InputType input_type) {
  // TODO(#27): Extend when more input types are supported.
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return "Cbor_MakeCredentialParameters";
    case InputType::kCborGetAssertionParameter:
      return "Cbor_GetAssertionParameters";
    case InputType::kCborRaw:
      return "Cbor_Raw";
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }
}

fido2_tests::Status SendInput(fido2_tests::DeviceInterface* device,
                              InputType input_type,
                              std::vector<uint8_t> const& input) {
  std::vector<uint8_t> response;
  // TODO(#27): Extend when more input types are supported.
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return device->ExchangeCbor(
          fido2_tests::Command::kAuthenticatorMakeCredential, input, false,
          &response);
    case InputType::kCborGetAssertionParameter:
      return device->ExchangeCbor(
          fido2_tests::Command::kAuthenticatorGetAssertion, input, false,
          &response);
    default:
      return fido2_tests::Status::kErrOther;
  }
}

}  // namespace corpus_tests

