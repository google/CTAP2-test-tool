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

// Default number of retries.
constexpr int kRetries = 3;

// Prints a line stating the file being mutated, rewriting the last line of
// output.
void PrintMutatingFile(std::string_view file_name, size_t last_file_name_len) {
  // Clean last line output in case the current line to be printed is shorter.
  std::cout << "\r                   "
            << std::string(last_file_name_len + 1, ' ');
  std::cout << "\rMutating from file " << file_name << ". " << std::flush;
}

void PrintFuzzingOptions(fuzzing_helpers::FuzzingOptions fuzzing_options) {
  std::cout << "\n|--- Fuzzer information ---|\n";
  std::cout << "Initial corpus path: " << fuzzing_options.corpus_path
            << InputTypeToDirectoryName(fuzzing_options.fuzzing_input_type)
            << "/\n";
  if (fuzzing_options.num_runs == 0) {
    std::cout
        << "--num_runs is not provided. The fuzzer will run indefinitely\n";
  } else {
    std::cout << "Number of runs: " << fuzzing_options.num_runs << "\n";
  }
  if (fuzzing_options.max_length == 0) {
    std::cout << "--max_length is not provided. There will be no limit\n";
  } else {
    std::cout << "Maximum input length: " << fuzzing_options.max_length << "\n";
  }
  std::cout << "Maximum mutation degree: "
            << fuzzing_options.max_mutation_degree << "\n";
  std::cout << "Seed: " << fuzzing_options.seed << "\n\n" << std::flush;
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
  PrintFuzzingOptions(fuzzing_options_);
  size_t last_input_name_len = 0;
  int iteration = 0;
  while (fuzzing_options_.num_runs == 0 ||
         iteration < fuzzing_options_.num_runs) {
    auto [mutated_input_data, seed_input_name] = GetNextInput();
    PrintMutatingFile(seed_input_name, last_input_name_len);
    fuzzing_helpers::SendInput(device, fuzzing_options_.fuzzing_input_type,
                               mutated_input_data);
    auto [device_crashed, observations] =
        monitor->DeviceCrashed(command_state, kRetries);
    if (device_crashed) {
      monitor->PrintCrashReport();
      std::string save_path =
          monitor->SaveCrashFile(fuzzing_options_.fuzzing_input_type,
                                 mutated_input_data, CurrentTimestampString());
      break;
    }
    last_input_name_len = seed_input_name.size();
    ++iteration;
  }
}

std::tuple<std::vector<uint8_t>, std::string> Fuzzer::GetNextInput() {
  auto [input_data, input_name] = corpus_controller_.GetRandomInput();
  mutator_.Mutate(input_data, fuzzing_options_.max_length);
  return {input_data, input_name};
}

}  // namespace fido2_tests

