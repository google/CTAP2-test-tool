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

#include "corpus_tests/monitor/gdb_monitor.h"

#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "glog/logging.h"

namespace corpus_tests {
namespace {

// Prints the details of the stop reply according to
// https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
void PrintStopReply(const std::string_view& response) {
  switch (response[0]) {
    case 'N':
      std::cout << "There are no resumed threads left in the target."
                << std::endl;
      break;
    case 'S':
      std::cout << "The program received signal: " << response.substr(1, 2)
                << std::endl;
      break;
    case 'T':
      std::cout << "The program received signal: " << response.substr(1, 2)
                << ", " << response.substr(3) << std::endl;
      break;
    case 'W':
      std::cout << "The process exited with exit status: "
                << response.substr(1, 2);
      if (response.size() > 3) {
        std::cout << ", " << response.substr(4);
      }
      std::cout << std::endl;
      break;
    case 'X':
      std::cout << "The process terminated with signal: "
                << response.substr(1, 2);
      if (response.size() > 3) {
        std::cout << ", " << response.substr(4);
      }
      std::cout << std::endl;
      break;
    default:
      break;
  }
}

}  // namespace

GdbMonitor::GdbMonitor(fido2_tests::DeviceInterface* device, int port) : Monitor(device), port_(port) {}

bool GdbMonitor::Attach() {
  if (!rsp_client_.Initialize() || !rsp_client_.Connect(port_)) {
    return false;
  }
  return rsp_client_.SendPacket(rsp::RspPacket(rsp::RspPacket::Continue));
}

bool GdbMonitor::DeviceCrashed() {
  auto response = rsp_client_.ReceivePacket();
  if (!response.has_value()) {
    return false;
  }
  stop_message_ = response.value();
  return true;
}

void GdbMonitor::PrintCrashReport() {
  PrintStopReply(stop_message_);
}

}  // namespace corpus_tests