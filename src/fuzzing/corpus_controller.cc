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

#include "src/fuzzing/corpus_controller.h"

#include <filesystem>
#include <fstream>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

namespace fido2_tests {
namespace {

// Returns the data and the name of the file at the given path.
std::tuple<std::vector<uint8_t>, std::string> GetDataFromFile(
    const std::string& input_path) {
  std::ifstream file(input_path, std::ios::in | std::ios::binary);
  std::vector<uint8_t> input_data = std::vector<uint8_t>(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  std::string input_name =
      static_cast<std::vector<std::string>>(absl::StrSplit(input_path, '/'))
          .back();
  return {input_data, input_name};
}

}  // namespace

CorpusController::CorpusController(fuzzing_helpers::InputType input_type,
                                   const std::string_view& base_corpus_path) {
  corpus_path_ =
      absl::StrCat(base_corpus_path, InputTypeToDirectoryName(input_type), "/");
  current_input_ = std::filesystem::directory_iterator(corpus_path_);
  corpus_size_ =
      std::distance(std::filesystem::directory_iterator(corpus_path_),
                    std::filesystem::directory_iterator());
}

bool CorpusController::HasNextInput() {
  return current_input_ != std::filesystem::directory_iterator();
}

std::tuple<std::vector<uint8_t>, std::string> CorpusController::GetNextInput() {
  std::string input_path = current_input_->path();
  ++current_input_;
  return GetDataFromFile(input_path);
}

std::tuple<std::vector<uint8_t>, std::string>
CorpusController::GetRandomInput() {
  std::filesystem::directory_iterator seed_input =
      std::filesystem::directory_iterator(corpus_path_);
  int index = std::rand() % corpus_size_;
  while (index--) {
    seed_input++;
  }
  return GetDataFromFile(seed_input->path());
}

}  // namespace fido2_tests

