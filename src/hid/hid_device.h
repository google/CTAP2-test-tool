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

#ifndef HID_HID_DEVICE_H_
#define HID_HID_DEVICE_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "hidapi/hidapi.h"
#include "src/constants.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"

namespace fido2_tests {
namespace hid {

struct __attribute__((__packed__)) Frame {
  static constexpr uint8_t kTypeInitMask = 0x80;
  static constexpr uint8_t kSeqMask = 0x80;

  uint32_t cid;
  union {
    uint8_t type;
    struct {
      uint8_t cmd;
      uint8_t bcnth;
      uint8_t bcntl;
      // The frame has 64 bytes, and cid(4) + cmd(1) + and bcn(2) take away 7.
      uint8_t data[64 - 7];
    } init;
    struct {
      uint8_t seq;
      // The frame has 64 bytes, and cid(4) + seq(1) take away 5.
      uint8_t data[64 - 5];
    } cont;
  };

  bool IsInitType() const { return type & Frame::kTypeInitMask; }

  uint8_t MaskedSeq() const { return cont.seq & ~kSeqMask; }

  size_t PayloadLength() const { return init.bcnth * 256u + init.bcntl; }
};

// Utility function that enumerates all connected HID devices that have the
// FIDO HID usage page (i.e. 0xf1d0) and prints their details on stdout.
void PrintFidoDevices();

// Utility function that returns the first suitable device path found.
std::string FindFirstFidoDevicePath();

class HidDevice : public DeviceInterface {
 public:
  // The constructor without the third parameter implicitly assumes false.
  // In both constructors, the ownership for tracker stays with the caller
  // and it must outlive the HidDevice instance. The device information is set
  // and sent to the tracker.
  HidDevice(DeviceTracker* tracker, std::string_view pathname);
  // Prepares the object for sending packets. The pathname points to the device.
  HidDevice(DeviceTracker* tracker, std::string_view pathname,
            bool verbose_logging);
  ~HidDevice() override;
  // In contrast to the constructor, Init sends a package to initilialize the
  // communication with the authenticator and establish a channel ID.
  Status Init() override;
  // Sends a Wink command to the device that usually makes it blink a LED.
  Status Wink() override;
  // Sends and receive CTAPHID_CBOR packages for exchanging CTAP2 commands.
  // Checks for the correct command byte in the response.
  Status ExchangeCbor(Command command, const std::vector<uint8_t>& payload,
                      bool expect_up_check,
                      std::vector<uint8_t>* response_cbor) const override;

 private:
  // A received response can be status 0, an error, or a keepalive in case the
  // authenticator still needs time for calculation or user presence. Call this
  // function with the received payload and wait for the next package.
  KeepaliveStatus ProcessKeepalive(const std::vector<uint8_t>& data) const;
  // Sends a CTAPHID command, possibly split into multiple frames.
  Status SendCommand(uint8_t cmd, const std::vector<uint8_t>& data) const;
  // Waits for incoming frames, returning their content in an output parameter.
  Status ReceiveCommand(absl::Duration timeout, uint8_t* cmd,
                        std::vector<uint8_t>* data) const;
  // The lowest abstraction layer, just sends a single frame.
  Status SendFrame(Frame* frame) const;
  // The lowest abstraction layer, receives a single frame with in a given time.
  Status ReceiveFrame(absl::Duration timeout, Frame* frame) const;
  void Log(std::string_view message) const;
  void Log(std::string_view direction, Frame* frame) const;
  // Scans connected HID devices for one with the same product ID as this device
  // and returns its filesystem path, or fails if none was found.
  std::string FindDevicePath();
  // Converts the status byte to the Status enum. If no variant corresponds to
  // the given byte, returns kErrOther instead and reports unexpected behaviour.
  Status ByteToStatus(uint8_t status_byte) const;

  // Points to a global test tracker to report findings.
  DeviceTracker* tracker_;
  // Set by the constructor, decides if the Log function actually print.
  bool verbose_logging_ = false;
  // This is the device from hdiapi.
  hid_device* dev_ = nullptr;
  // Will be set in Init, starts as broadcast.
  uint32_t cid_ = 0;
  // Kept constant for determinism, might get a setter.
  unsigned int seed_ = 0;
  // This device's vendor & product ID (in this order) are used for reconnects.
  const DeviceIdentifiers device_identifiers_;
};

}  // namespace hid
}  // namespace fido2_tests

#endif  // HID_HID_DEVICE_H_

