// Copyright 2019 Google LLC
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

#include "src/device_interface.h"

namespace corpus_tests {

class TestInputController {
 public:
  TestInputController(std::string corpus_path);
  TestInputController(bool fuzzing, std::string corpus_path);
  // Returns whether there is an input available.
  bool InputAvailable();
  // Updates current input iterator.
  void GetNextInput();
  // Sends current input to the given device.
  fido2_tests::Status RunCurrentInput(fido2_tests::DeviceInterface* device);

 private:
  // By default, when no corpus is given, enable fuzzing from zero.
  bool fuzzing_ = true;
  std::filesystem::directory_iterator current_input_;
};

}  // namespace corpus_tests

#endif  // TEST_INPUT_CONTROLLER_H_
