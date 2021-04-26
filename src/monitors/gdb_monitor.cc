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

#include "src/monitors/gdb_monitor.h"

#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "glog/logging.h"

namespace fido2_tests {

// Default number of retries.
constexpr int kRetries = 10;

GdbMonitor::GdbMonitor(int port) : port_(port) {}

void GdbMonitor::PrintStopReply(const std::string_view& response) {
  if (response.empty()) {
    return;
  }
  switch (response[0]) {
    case 'N':
      std::cout << "There are no resumed threads left in the target."
                << std::endl;
      break;
    case 'S':
      CHECK(response.size() == 3) << "Wrong packet length";
      std::cout << "The program received signal: " << response.substr(1, 2)
                << std::endl;
      break;
    case 'T':
      CHECK(response.size() >= 3) << "Wrong packet length";
      std::cout << "The program received signal: " << response.substr(1, 2)
                << ", " << response.substr(3) << std::endl;
      break;
    case 'W':
      CHECK(response.size() >= 3) << "Wrong packet length";
      std::cout << "The process exited with exit status: "
                << response.substr(1, 2);
      if (response.size() > 3) {
        std::cout << ", " << response.substr(4);
      }
      std::cout << std::endl;
      break;
    case 'X':
      CHECK(response.size() >= 3) << "Wrong packet length";
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

bool GdbMonitor::Attach() {
  return rsp_client_.Initialize() && rsp_client_.Connect(port_);
}

bool GdbMonitor::Prepare(CommandState* command_state) {
  command_state->PromptReplugAndInit();
  return rsp_client_.SendPacket(rsp::RspPacket(rsp::RspPacket::Continue),
                                kRetries);
}

std::tuple<bool, std::vector<std::string>> GdbMonitor::DeviceCrashed(
    CommandState* command_state, int retries) {
  auto response = rsp_client_.ReceivePacket();
  if (!response.has_value()) {
    return {false, {}};
  }
  stop_message_ = response.value();
  return {true, {}};
}

void GdbMonitor::PrintCrashReport() {
  Monitor::PrintCrashReport();
  PrintStopReply(stop_message_);
}

}  // namespace fido2_tests

