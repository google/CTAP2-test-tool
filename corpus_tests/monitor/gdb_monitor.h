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

#ifndef GDB_MONITOR_H_
#define GDB_MONITOR_H_

#include "corpus_tests/monitor/monitor.h"
#include "corpus_tests/rsp/rsp.h"

namespace corpus_tests {

// A Monitor that detects crashes by communicating with a GDB remote
// serial protocol server on the target.
class GdbMonitor : public Monitor {
 public:
  GdbMonitor(int port);
  // Attaches the monitor to a device by connecting to the port
  // device's GDB server is listening to, and sends "continue" command
  // to the target. This will execute the program until a
  // crash triggers a breakpoint.
  bool Attach() override;
  // Checks for an occured failure in the device by attempting to
  // receive data from the RSP server.
  bool DeviceCrashed() override;
  // Prints the stop response received from the RSP server.
  void PrintCrashReport() override;
  // Prints the details of the stop reply according to
  // https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
  void PrintStopReply(const std::string_view& response);

 protected:
  // Returns the pointer to the rsp client.
  rsp::RemoteSerialProtocol* GetRspClient() { return &rsp_client_; }

 private:
  int port_;
  rsp::RemoteSerialProtocol rsp_client_;
  std::string stop_message_;
};

}  // namespace corpus_tests

#endif  // GDB_MONITOR_H_
