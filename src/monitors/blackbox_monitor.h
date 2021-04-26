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

#ifndef BLACKBOX_MONITOR_H_
#define BLACKBOX_MONITOR_H_

#include "src/command_state.h"
#include "src/monitors/monitor.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// A Monitor that detects a hang or a reboot after crash on the given device.
class BlackboxMonitor : public Monitor {
 public:
  // Prepares for further crash detection by setting up an initial pin token.
  bool Prepare(CommandState* command_state) override;
  // Checks for an occured failure in the device through the identification of a
  // hang (no response) or a reboot after crash by comparing the pin token of
  // the security key.
  std::tuple<bool, std::vector<std::string>> DeviceCrashed(
      CommandState* command_state, int retries = 1) override;

 private:
  cbor::Value initial_key_agreement_;
};

}  // namespace fido2_tests

#endif  // BLACKBOX_MONITOR_H_

