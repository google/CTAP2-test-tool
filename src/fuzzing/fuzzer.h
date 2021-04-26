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

#ifndef FUZZING_FUZZER_H_
#define FUZZING_FUZZER_H_

#include "src/command_state.h"
#include "src/fuzzing/corpus_controller.h"
#include "src/fuzzing/fuzzing_helpers.h"
#include "src/fuzzing/mutator.h"
#include "src/hid/hid_device.h"
#include "src/monitors/monitor.h"

namespace fido2_tests {

// Mutation-based fuzzer designed for CTAP2 commands.
// Please check src/fuzzing/fuzzing_helpers.h for all supported input types and
// fuzzing options.
class Fuzzer {
 public:
  Fuzzer(fuzzing_helpers::FuzzingOptions fuzzing_options);
  // Starts fuzzing and sending the inputs to the given device while tracking
  // device crash with the given monitor.
  void Run(CommandState* command_state, DeviceInterface* device,
           Monitor& monitor);

 private:
  // Returns a new mutated input and its assigned file name.
  std::tuple<std::vector<uint8_t>, std::string> CreateNextInput();

  fuzzing_helpers::FuzzingOptions fuzzing_options_;
  CorpusController corpus_controller_;
};

}  // namespace fido2_tests

#endif  // FUZZING_FUZZER_H_

