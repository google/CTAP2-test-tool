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

#ifndef MONITOR_H_
#define MONITOR_H_

#include <string>
#include <tuple>
#include <vector>

#include "src/command_state.h"
#include "src/fuzzing/corpus_controller.h"

namespace fido2_tests {

// Base class that tracks crashes on a given device.
// Example:
//   fido2_tests::Monitor monitor;
//   monitor.Attach();
//   monitor.Prepare();
//   if (monitor.DeviceCrashed()) {
//     monitor.PrintCrashReport();
//     monitor.SaveCrashFile();
//   }
class Monitor {
 public:
  virtual ~Monitor() = default;
  // Attaches the monitor to a device if needed. By default it's not necessary.
  virtual bool Attach() { return true; };
  // Prepares the necessary steps to monitor the device. By default there are
  // none.
  virtual bool Prepare(CommandState* command_state) { return true; };
  // Checks for an occured failure in the device with retry and also returns
  // observations occured during monitoring. Every derived monitor should
  // provide an implementation of this function.
  virtual std::tuple<bool, std::vector<std::string>> DeviceCrashed(
      CommandState* command_state, int retries = 1) = 0;
  // Prints some information about the produced crash on the device
  // and/or the state of the device.
  virtual void PrintCrashReport();
  // Saves the given file crashing the device in the artifacts directory.
  // Returns the path of the saved file.
  std::string SaveCrashFile(fuzzing_helpers::InputType input_type,
                            const std::vector<uint8_t>& data,
                            const std::string_view& file_name);
};

}  // namespace fido2_tests

#endif  // MONITOR_H_

