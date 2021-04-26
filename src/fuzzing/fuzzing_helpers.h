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

#ifndef FUZZING_FUZZING_HELPERS_H_
#define FUZZING_FUZZING_HELPERS_H_

#include <string>
#include <vector>

#include "src/device_interface.h"

namespace fido2_tests {

namespace fuzzing_helpers {

// Possible input types.
enum InputType {
  kCborMakeCredentialParameter,
  kCborGetAssertionParameter,
  kCborClientPinParameter,
  kCborRaw,
  kRawData
};

struct FuzzingOptions {
  std::string corpus_path;
  InputType fuzzing_input_type;
  int num_runs = 0;
  int max_length = 0;
  int max_mutation_degree = 10;
  int seed = time(NULL);
};

// Converts an InputType to the corresponding directory name.
std::string InputTypeToDirectoryName(InputType input_type);

// Sends input to the given device and returns the status code.
Status SendInput(DeviceInterface* device, InputType input_type,
                 std::vector<uint8_t> const& input);

}  // namespace fuzzing_helpers
}  // namespace fido2_tests

#endif  // FUZZING_FUZZING_HELPERS_H_

