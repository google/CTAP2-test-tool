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

#include "src/device_interface.h"

namespace fido2_tests {

// Possible input types.
enum InputType {
  kCborMakeCredentialParameter,
  kCborGetAssertionParameter,
  kCborRaw,
  kRawBytes
};

// Converts an InputType to the corresponding directory name.
std::string InputTypeToDirectoryName(InputType input_type);

// Sends input to the given device and returns the status code.
Status SendInput(DeviceInterface* device, InputType input_type,
                 std::vector<uint8_t> const& input);

// Iterates input files of the given type from a given corpus.
// We assume the corpus directory to contain subdirectories for
// each type of inputs. For example, given directory /corpus,
// all possible subdirectories are:
//  /corpus/Cbor_MakeCredentialParameters/
//  /corpus/Cbor_GetAssertionParameters/
// TODO (mingxguo) issue #27
// All files that are not a directory in the given corpus are ignored.
class CorpusIterator {
 public:
  CorpusIterator(InputType input_type,
                 const std::string_view& base_corpus_path);
  // Returns whether there is a next input available.
  bool HasNextInput();
  // Returns the content and the file name of the next available input.
  std::tuple<std::vector<uint8_t>, std::string> GetNextInput();

 private:
  std::filesystem::directory_iterator current_input_;
};

}  // namespace fido2_tests

#endif  // CORPUS_CONTROLLER_H_

