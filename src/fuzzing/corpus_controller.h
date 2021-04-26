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

#ifndef FUZZING_CORPUS_CONTROLLER_H_
#define FUZZING_CORPUS_CONTROLLER_H_

#include <cstdint>
#include <filesystem>
#include <tuple>
#include <vector>

#include "src/fuzzing/fuzzing_helpers.h"

namespace fido2_tests {

// Manages the corpus containing input files of the given type.
// We assume the root corpus directory to contain subdirectories for
// each type of inputs. For example, given directory /corpus,
// all possible subdirectories are:
//  /corpus/Cbor_MakeCredentialParameters/
//  /corpus/Cbor_GetAssertionParameters/
//  /corpus/Cbor_ClientPinParameters/
//  /corpus/CtapHidRawData/
// TODO (mingxguo) issue #27
class CorpusController {
 public:
  CorpusController(fuzzing_helpers::InputType input_type,
                   const std::string_view& base_corpus_path);
  // Returns whether there is a next input file available in an iterative
  // manner.
  bool HasNextInput();
  // Returns the content and the name of the next available input file in an
  // iterative manner.
  std::tuple<std::vector<uint8_t>, std::string> GetNextInput();
  // Returns the content and the name of a random input file, independently from
  // the iterative mode.
  std::tuple<std::vector<uint8_t>, std::string> GetRandomInput();

 private:
  // Returns the data of the file with the given name.
  std::vector<uint8_t> GetFileData(const std::string& file_name);

  struct FileMetadata {
    std::uintmax_t file_size;
    std::string file_name;
    bool operator<(const FileMetadata& other) const {
      return (file_size < other.file_size) ||
             (file_size == other.file_size && file_name < other.file_name);
    }
  };
  std::filesystem::path corpus_path_;
  std::vector<FileMetadata> corpus_metadata_;
  // An index in the vector of corpus metadata pointing to the current file
  // under iteration.
  size_t current_input_index_ = 0;
};

}  // namespace fido2_tests

#endif  // FUZZING_CORPUS_CONTROLLER_H_

