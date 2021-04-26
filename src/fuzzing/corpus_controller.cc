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

#include "src/fuzzing/corpus_controller.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>

#include "glog/logging.h"

namespace fido2_tests {

// Returns the file data at the given path.
std::vector<uint8_t> CorpusController::GetFileData(
    const std::string& file_name) {
  std::filesystem::path input_path = corpus_path_ / file_name;
  std::ifstream input_file(input_path, std::ios::in | std::ios::binary);
  CHECK(input_file.is_open()) << "Unable to open file: " << input_path;
  std::vector<uint8_t> input_data =
      std::vector<uint8_t>((std::istreambuf_iterator<char>(input_file)),
                           std::istreambuf_iterator<char>());
  return input_data;
}

CorpusController::CorpusController(fuzzing_helpers::InputType input_type,
                                   const std::string_view& base_corpus_path)
    : corpus_path_(base_corpus_path) {
  corpus_path_ /= InputTypeToDirectoryName(input_type);
  // Construct corpus metadata and sort by file size, then by file name.
  for (auto& corpus_iter : std::filesystem::directory_iterator(corpus_path_)) {
    std::uintmax_t file_size = std::filesystem::file_size(corpus_iter.path());
    std::string file_name = corpus_iter.path().filename();
    corpus_metadata_.push_back({file_size, file_name});
  }
  sort(corpus_metadata_.begin(), corpus_metadata_.end());
}

bool CorpusController::HasNextInput() {
  return current_input_index_ < corpus_metadata_.size();
}

std::tuple<std::vector<uint8_t>, std::string> CorpusController::GetNextInput() {
  std::string input_name = corpus_metadata_[current_input_index_].file_name;
  ++current_input_index_;
  return {GetFileData(input_name), input_name};
}

std::tuple<std::vector<uint8_t>, std::string>
CorpusController::GetRandomInput() {
  int index = std::rand() % corpus_metadata_.size();
  return {GetFileData(corpus_metadata_[index].file_name),
          corpus_metadata_[index].file_name};
}

}  // namespace fido2_tests

