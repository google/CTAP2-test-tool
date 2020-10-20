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

#ifndef MONITOR_H_
#define MONITOR_H_

#include "corpus_tests/test_input_controller.h"
#include "src/device_interface.h"

namespace corpus_tests {

// Base class for a monitor in charge of tracking crash on a given device.
// Example:
//   corpus_tests::Monitor monitor;
//   monitor.Attach();
//   if (monitor.DeviceCrashed()) {
//     monitor.PrintCrashReport();
//     monitor.SaveCrashFile();
//   }
class Monitor {
 public:
  Monitor(fido2_tests::DeviceInterface* device);
  // Attaches the monitor to a device if needed. By default it's not necessary.
  virtual bool Attach() { return true; };
  // Checks for an occured failure in the device. Every derived monitor should
  // provide an implementation of this function.
  virtual bool DeviceCrashed() = 0;
  // Prints some information about the produced crash on the device
  // and/or the state of the device.
  virtual void PrintCrashReport(){};
  // Saves the given file crashing the device in the artifacts directory.
  void SaveCrashFile(InputType input_type, std::string_view const& input_path);

 protected:
  fido2_tests::DeviceInterface* device_;
};

}  // namespace corpus_tests

#endif  // MONITOR_H_
