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

#include "src/corpus_controller.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "glog/logging.h"

namespace fido2_tests {

CorpusIterator::CorpusIterator(InputType input_type,
                               const std::string_view& base_corpus_path) {
  std::string test_corpus_path =
      absl::StrCat(base_corpus_path, InputTypeToDirectoryName(input_type), "/");
  current_input_ = std::filesystem::directory_iterator(test_corpus_path);
}

bool CorpusIterator::HasNextInput() {
  return current_input_ != std::filesystem::directory_iterator();
}

std::tuple<std::vector<uint8_t>, std::string> CorpusIterator::GetNextInput() {
  std::string input_path = current_input_->path();
  std::ifstream file(current_input_->path(), std::ios::in | std::ios::binary);
  std::vector<uint8_t> input_data = std::vector<uint8_t>(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  ++current_input_;
  return {input_data, input_path};
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

Status SendInput(DeviceInterface* device, InputType input_type,
                 std::vector<uint8_t> const& input) {
  std::vector<uint8_t> response;
  // TODO(#27): Extend when more input types are supported.
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return device->ExchangeCbor(Command::kAuthenticatorMakeCredential, input,
                                  false, &response);
    case InputType::kCborGetAssertionParameter:
      return device->ExchangeCbor(Command::kAuthenticatorGetAssertion, input,
                                  false, &response);
    default:
      return Status::kErrOther;
  }
}

}  // namespace fido2_tests

