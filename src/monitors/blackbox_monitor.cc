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

#include "src/monitors/blackbox_monitor.h"

#include <iostream>

#include "glog/logging.h"

namespace fido2_tests {

bool BlackboxMonitor::Prepare(CommandState* command_state) {
  bool ok = command_state->GetAuthToken() == Status::kErrNone;
  if (ok) {
    initial_pin_token_ = command_state->GetCurrentAuthToken();
  }
  return ok;
}

bool BlackboxMonitor::DeviceCrashed(CommandState* command_state) {
  if (command_state->GetAuthToken() != Status::kErrNone) {
    return true;
  }
  return command_state->GetCurrentAuthToken() != initial_pin_token_;
}

}  // namespace fido2_tests

