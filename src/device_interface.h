// Copyright 2019-2021 Google LLC
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

#ifndef DEVICE_INTERFACE_H_
#define DEVICE_INTERFACE_H_

#include <vector>

#include "src/constants.h"

namespace fido2_tests {

// This is the abstract base class for all possible interfaces: HID, NFC, BLE.
// If you forget to call Init() after the constructor, you might get error
// status codes on ExchangeCbor calls.
// To inherit from this class, you need to implement the Init and ExchangeCbor
// functions, and most likely constructor and destructor.
// Currently, you are only supposed have one instance for a given device.
class DeviceInterface {
 public:
  virtual ~DeviceInterface() = default;
  virtual Status Init() = 0;
  virtual Status Wink() = 0;
  // As part of a CBOR exchange, the user might be prompted for user presence.
  // expect_up_check specifies the desired outcome and warns otherwise.
  // The last argument response_cbor is an output parameter.
  virtual Status ExchangeCbor(Command command,
                              const std::vector<uint8_t>& payload,
                              bool expect_up_check,
                              std::vector<uint8_t>* response_cbor) const = 0;
};

// Contains all device identifier for logging and to re-identify the device.
struct DeviceIdentifiers {
  std::string manufacturer;
  std::string product_name;
  std::string serial_number;
  uint16_t vendor_id;
  uint16_t product_id;
};

}  // namespace fido2_tests

#endif  // DEVICE_INTERFACE_H_

