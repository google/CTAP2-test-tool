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

#ifndef BLACKBOX_MONITOR_H_
#define BLACKBOX_MONITOR_H_

#include "corpus_tests/monitor/monitor.h"
#include "src/hid/hid_device.h"
#include "third_party/chromium_components_cbor/values.h"

namespace corpus_tests {

// A Monitor that detects a hang or a reboot after crash on the given device.
class BlackboxMonitor : public Monitor {
 public:
  BlackboxMonitor(fido2_tests::DeviceInterface* device,
                  fido2_tests::DeviceTracker* device_tracker);
  // Attaches the monitor to a device for further crash detection by
  // setting up an initial pin token.
  bool Attach() override;
  // Checks for an occured failure in the device through the identification of a
  // hang (no response) or a reboot after crash by comparing the pin token of
  // the security key.
  bool DeviceCrashed() override;

 private:
  // TODO(mingxguo): the following methods need refactoring with master branch.
  // Gets the shared secret from the device.
  void ComputeSharedSecret();
  // Sets up a default pin on the device.
  void SetDefaultPin();
  // Returns the pin token of the device if operation successful.
  std::optional<cbor::Value::BinaryValue> GetAuthToken();

  fido2_tests::DeviceInterface* device_;
  fido2_tests::DeviceTracker* device_tracker_;
  cbor::Value::BinaryValue initial_pin_token_;
  cbor::Value::BinaryValue shared_secret_;
  cbor::Value::MapValue platform_cose_key_;
};

}  // namespace corpus_tests

#endif  // BLACKBOX_MONITOR_H_
