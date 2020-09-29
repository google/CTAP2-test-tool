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

#ifndef MONITOR_H_
#define MONITOR_H_

#include "rsp/rsp.h"
#include "src/device_interface.h"

namespace corpus_tests {

// Monitors and reports crash on a given device by communicating with
// its GDB remote serial protocol server.
// Example:
//   corpus_tests::Monitor monitor;
//   monitor.Attach(device, port);
//   monitor.Start();
//   if (monitor.DeviceCrashed()) { ... }
class Monitor {
 public:
  // Attaches the monitor to a device and connects to the port
  // device's GDB server is listening to.
  bool Attach(fido2_tests::DeviceInterface* device, int port);
  // Starts monitoring the attached device by sending "continue"
  // command to the target. This will execute the program until a
  // crash triggers a breakpoint.
  bool Start();
  // Checks for an occured failure in the device by attempting to
  // receive data from the RSP server.
  bool DeviceCrashed();

 private:
  rsp::RemoteSerialProtocol rsp_client_;
  fido2_tests::DeviceInterface* device_;
};

}  // namespace corpus_tests

#endif  // MONITOR_H_
