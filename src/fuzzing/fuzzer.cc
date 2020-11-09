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

#include "src/fuzzing/fuzzer.h"

#include <iostream>
#include <string>
#include <vector>

namespace fido2_tests {
namespace {

// Prints a line stating the file being mutated, rewriting the last line of
// output.
void PrintMutatingFile(std::string_view file_name, size_t last_file_name_len) {
  // Clean last line output in case the current line to be printed is shorter.
  std::cout << "\r                   " << std::string(last_file_name_len, ' ');
  std::cout << "\rMutating from file " << file_name << ". " << std::flush;
}

// Returns the string of the current timestamp in microseconds since epoch.
// Placeholder for the fuzzing input's filename.
std::string CurrentTimestampString() {
  return std::to_string(
      std::chrono::system_clock::now().time_since_epoch().count());
}

}  // namespace

Fuzzer::Fuzzer(fuzzing_helpers::FuzzingOptions fuzzing_options)
    : fuzzing_options_(fuzzing_options),
      corpus_controller_(CorpusController(fuzzing_options.fuzzing_input_type,
                                          fuzzing_options.corpus_path)),
      mutator_(
          Mutator(fuzzing_options.max_mutation_degree, fuzzing_options.seed)) {
  srand(fuzzing_options.seed);
}

void Fuzzer::Run(CommandState* command_state, DeviceInterface* device,
                 Monitor* monitor) {
  size_t last_input_name_len = 0;
  while (1) {  // TODO: add num_runs
    auto [mutated_input_data, seed_input_name] = GetNextInput();
    PrintMutatingFile(seed_input_name, last_input_name_len);
    fuzzing_helpers::SendInput(device, fuzzing_options_.fuzzing_input_type,
                               mutated_input_data);
    if (monitor->DeviceCrashed(command_state)) {
      monitor->PrintCrashReport();
      std::string save_path =
          monitor->SaveCrashFile(fuzzing_options_.fuzzing_input_type,
                                 mutated_input_data, CurrentTimestampString());
      break;
    }
    last_input_name_len = seed_input_name.size();
  }
}

std::tuple<std::vector<uint8_t>, std::string> Fuzzer::GetNextInput() {
  auto [input_data, input_name] = corpus_controller_.GetRandomInput();
  mutator_.Mutate(input_data, fuzzing_options_.max_length);
  return {input_data, input_name};
}

}  // namespace fido2_tests

