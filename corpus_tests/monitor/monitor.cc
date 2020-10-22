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

#include "corpus_tests/monitor/monitor.h"

#include <filesystem>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "glog/logging.h"

namespace corpus_tests {
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
  std::cout << "DEVICE CRASHED!" << std::endl;
}

void Monitor::SaveCrashFile(InputType input_type,
                            const std::string_view& input_path) {
  std::string input_name =
      static_cast<std::vector<std::string>>(absl::StrSplit(input_path, '/'))
          .back();
  std::filesystem::path save_path = absl::StrCat(
      CreateArtifactsSubdirectory(InputTypeToDirectoryName(input_type)), "/",
      input_name, 1);
  std::cout << "Saving file to " << save_path << std::endl;
  if (!std::filesystem::copy_file(
          input_path, save_path,
          std::filesystem::copy_options::skip_existing)) {
    CHECK(std::filesystem::exists(save_path)) << "Unable to save file!";
  }
}

}  // namespace corpus_tests