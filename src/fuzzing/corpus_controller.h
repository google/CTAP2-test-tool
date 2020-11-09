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

#ifndef CORPUS_CONTROLLER_H_
#define CORPUS_CONTROLLER_H_

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
// TODO (mingxguo) issue #27
// All files that are not a directory in the given corpus are ignored.
class CorpusController {
 public:
  CorpusController(fuzzing_helpers::InputType input_type,
                   const std::string_view& base_corpus_path);
  // Returns whether there is a next input file available.
  bool HasNextInput();
  // Returns the content and the name of the next available input file.
  std::tuple<std::vector<uint8_t>, std::string> GetNextInput();
  // Returns the content and the name of a random input file.
  std::tuple<std::vector<uint8_t>, std::string> GetRandomInput();

 private:
  std::filesystem::directory_iterator current_input_;
  size_t corpus_size_;
  std::string corpus_path_;
};

}  // namespace fido2_tests

#endif  // CORPUS_CONTROLLER_H_

