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

#include "src/monitors/monitor.h"

#include <filesystem>
#include <fstream>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "glog/logging.h"
#include "src/fuzzing/fuzzing_helpers.h"

namespace fido2_tests {
namespace {
constexpr std::string_view kRelativeDir = "corpus_tests/artifacts";

// Creates a directory for files that caused a crash and a subdirectory
// of the given name. Also returns the path.
// Just return the path if that directory already exists. Fails if the
// directory wasn't created successfully.
std::string CreateArtifactsSubdirectory(const std::string_view& subdirectory) {
  std::string results_dir = std::string(kRelativeDir);
  if (const char* env_dir = std::getenv("BUILD_WORKSPACE_DIRECTORY")) {
    results_dir = absl::StrCat(env_dir, "/", results_dir);
  }
  std::filesystem::create_directory(results_dir);  // creates artifact directory
  results_dir = absl::StrCat(results_dir, "/", subdirectory);
  std::filesystem::create_directory(results_dir);  // creates subdirectory
  return results_dir;
}

}  // namespace

void Monitor::PrintCrashReport() {
  std::cout << "\nDEVICE CRASHED!" << std::endl;
}

std::string Monitor::SaveCrashFile(fuzzing_helpers::InputType input_type,
                                   const std::vector<uint8_t>& data,
                                   const std::string_view& file_name) {
  std::filesystem::path save_path =
      absl::StrCat(CreateArtifactsSubdirectory(
                       fuzzing_helpers::InputTypeToDirectoryName(input_type)),
                   "/", file_name);
  std::ofstream crash_file(save_path, std::ios::out | std::ios::binary);
  CHECK(crash_file.is_open()) << "Unable to open file: " << save_path;
  crash_file.write(reinterpret_cast<const char*>(&data[0]),
                   data.size() * sizeof(uint8_t));
  crash_file.close();
  std::cout << "Saving file to " << save_path << std::endl;
  return save_path.string();
}

}  // namespace fido2_tests

