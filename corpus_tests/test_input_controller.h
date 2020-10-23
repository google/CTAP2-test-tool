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

#ifndef TEST_INPUT_CONTROLLER_H_
#define TEST_INPUT_CONTROLLER_H_

#include <filesystem>
#include <tuple>
#include <vector>

#include "src/device_interface.h"

namespace corpus_tests {

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
fido2_tests::Status SendInput(fido2_tests::DeviceInterface* device,
                              InputType input_type,
                              std::vector<uint8_t> const& input);

// Iterates input files from a given corpus.
// We assume the corpus directory to contain subdirectories for
// each type of inputs. For example, given directory /corpus,
// all possible subdirectories are:
//  /corpus/Cbor_MakeCredentialParameters/
//  /corpus/Cbor_GetAssertionParameters/
// TODO (mingxguo) issue #27
// All files that are not a directory in the given corpus are ignored.
class CorpusIterator {
 public:
  CorpusIterator(std::string_view corpus_path);
  // Returns whether there is a next input available.
  bool HasNextInput();
  // Returns the type, the content and the file name of the next available
  // input.
  std::tuple<InputType, std::vector<uint8_t>, std::string> GetNextInput();

 private:
  // Increments the current input pointer to the next non empty one
  // (potentially skipping all empty subdirectories).
  void UpdateInputPointer();
  std::filesystem::directory_iterator current_subdirectory_;
  std::filesystem::directory_iterator current_input_;
};

}  // namespace corpus_tests

#endif  // TEST_INPUT_CONTROLLER_H_

