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

#include "src/hid/hid_device.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "glog/logging.h"
#include "src/constants.h"

namespace fido2_tests {
namespace hid {
namespace {
constexpr int kHidDeviceRetries = 10;
// Transaction constants
constexpr size_t kInitNonceSize = 8;
constexpr size_t kInitRespSize = 17;
constexpr size_t kMaxDataSize = 7609;
constexpr uint32_t kIdBroadcast = 0xFFFFFFFF;
constexpr absl::Duration kReceiveTimeout = absl::Milliseconds(5000);
constexpr uint8_t kWinkCapabilityMask = 0x01;
constexpr uint8_t kCborCapabilityMask = 0x04;
constexpr uint8_t kNmsgCapabilityMask = 0x08;
constexpr uint8_t kCtap2ErrCborParsingRemovedStatus = 0x10;
constexpr uint8_t kCtap2ErrInvalidCborTypeRemovedStatus = 0x13;
constexpr uint8_t kCtap2ErrExtensionFirst = 0xE0;
constexpr uint8_t kCtap2ErrExtensionLast = 0xEF;
constexpr uint8_t kCtap2ErrVendorFirst = 0xF0;
constexpr uint8_t kCtap2ErrVendorLast = 0xF8;
// Commands in U2F
constexpr uint8_t kCtapHidPing = Frame::kTypeInitMask | 1;  // NOLINT
constexpr uint8_t kCtapHidMsg = Frame::kTypeInitMask | 3;   // NOLINT
constexpr uint8_t kCtapHidLock = Frame::kTypeInitMask | 4;  // NOLINT
constexpr uint8_t kCtapHidInit = Frame::kTypeInitMask | 6;
constexpr uint8_t kCtapHidWink = Frame::kTypeInitMask | 8;
constexpr uint8_t kCtapHidSync = Frame::kTypeInitMask | 0x3c;  // NOLINT
constexpr uint8_t kCtapHidError = Frame::kTypeInitMask | 0x3f;
// Commands new in FIDO2
constexpr uint8_t kCtapHidCbor = Frame::kTypeInitMask | 0x10;
constexpr uint8_t kCtapHidCancel = Frame::kTypeInitMask | 0x11;  // NOLINT
constexpr uint8_t kCtapHidKeepalive = Frame::kTypeInitMask | 0x3b;

void PromptUser() {
  std::cout << "Please touch your security key!" << std::endl;
}

// This function outputs the vendor & product ID for a HID device at a given
// path, for example "/dev/hidraw4".
DeviceIdentifiers ReadDeviceIdentifiers(std::string_view pathname) {
  hid_device_info* devs = hid_enumerate(0, 0);  // 0 means all devices
  for (hid_device_info* cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
    if (cur_dev->path == pathname) {
      std::wstring manufacturer = cur_dev->manufacturer_string;
      std::wstring product_name = cur_dev->product_string;
      std::wstring serial_number = cur_dev->serial_number;
      DeviceIdentifiers identifiers = {
          .manufacturer = std::string(manufacturer.begin(), manufacturer.end()),
          .product_name = std::string(product_name.begin(), product_name.end()),
          .serial_number =
              std::string(serial_number.begin(), serial_number.end()),
          .vendor_id = cur_dev->vendor_id,
          .product_id = cur_dev->product_id};
      hid_free_enumeration(devs);
      CHECK(identifiers.vendor_id != 0 && identifiers.product_id != 0)
          << "The device needs a non-zero vendor and product ID.";
      return identifiers;
    }
  }

  hid_free_enumeration(devs);
  CHECK(false) << "There was no device at path: " << pathname;
}

bool IsKnownStatusByte(uint8_t status_byte) {
  switch (status_byte) {
    case static_cast<uint8_t>(Status::kErrNone):
    case static_cast<uint8_t>(Status::kErrInvalidCommand):
    case static_cast<uint8_t>(Status::kErrInvalidParameter):
    case static_cast<uint8_t>(Status::kErrInvalidLength):
    case static_cast<uint8_t>(Status::kErrInvalidSeq):
    case static_cast<uint8_t>(Status::kErrTimeout):
    case static_cast<uint8_t>(Status::kErrChannelBusy):
    case static_cast<uint8_t>(Status::kErrLockRequired):
    case static_cast<uint8_t>(Status::kErrInvalidChannel):
    case static_cast<uint8_t>(Status::kErrCborUnexpectedType):
    case static_cast<uint8_t>(Status::kErrInvalidCbor):
    case static_cast<uint8_t>(Status::kErrMissingParameter):
    case static_cast<uint8_t>(Status::kErrLimitExceeded):
    case static_cast<uint8_t>(Status::kErrUnsupportedExtension):
    case static_cast<uint8_t>(Status::kErrCredentialExcluded):
    case static_cast<uint8_t>(Status::kErrProcessing):
    case static_cast<uint8_t>(Status::kErrInvalidCredential):
    case static_cast<uint8_t>(Status::kErrUserActionPending):
    case static_cast<uint8_t>(Status::kErrOperationPending):
    case static_cast<uint8_t>(Status::kErrNoOperations):
    case static_cast<uint8_t>(Status::kErrUnsupportedAlgorithm):
    case static_cast<uint8_t>(Status::kErrOperationDenied):
    case static_cast<uint8_t>(Status::kErrKeyStoreFull):
    case static_cast<uint8_t>(Status::kErrNoOperationPending):
    case static_cast<uint8_t>(Status::kErrUnsupportedOption):
    case static_cast<uint8_t>(Status::kErrInvalidOption):
    case static_cast<uint8_t>(Status::kErrKeepaliveCancel):
    case static_cast<uint8_t>(Status::kErrNoCredentials):
    case static_cast<uint8_t>(Status::kErrUserActionTimeout):
    case static_cast<uint8_t>(Status::kErrNotAllowed):
    case static_cast<uint8_t>(Status::kErrPinInvalid):
    case static_cast<uint8_t>(Status::kErrPinBlocked):
    case static_cast<uint8_t>(Status::kErrPinAuthInvalid):
    case static_cast<uint8_t>(Status::kErrPinAuthBlocked):
    case static_cast<uint8_t>(Status::kErrPinNotSet):
    case static_cast<uint8_t>(Status::kErrPinRequired):
    case static_cast<uint8_t>(Status::kErrPinPolicyViolation):
    case static_cast<uint8_t>(Status::kErrPinTokenExpired):
    case static_cast<uint8_t>(Status::kErrRequestTooLarge):
    case static_cast<uint8_t>(Status::kErrActionTimeout):
    case static_cast<uint8_t>(Status::kErrUpRequired):
    case static_cast<uint8_t>(Status::kErrUvBlocked):
    case static_cast<uint8_t>(Status::kErrOther):
      return true;
    default:
      return false;
  }
}
}  // namespace

HidDevice::HidDevice(DeviceTracker* tracker, std::string_view pathname)
    : HidDevice(tracker, pathname, /* verbose_logging = */ false) {}

HidDevice::HidDevice(DeviceTracker* tracker, std::string_view pathname,
                     bool verbose_logging)
    : tracker_(tracker),
      verbose_logging_(verbose_logging),
      device_identifiers_(ReadDeviceIdentifiers(pathname)) {
  std::cout << "Tested device name: " << device_identifiers_.product_name
            << std::endl;
  tracker_->SetDeviceIdentifiers(device_identifiers_);
}

HidDevice::~HidDevice() {
  if (dev_) {
    hid_close(dev_);
    dev_ = nullptr;
  }
}

Status HidDevice::Init() {
  if (dev_) {
    hid_close(dev_);
    dev_ = nullptr;
  }

  std::string device_path = FindDevicePath();
  dev_ = hid_open_path(device_path.c_str());
  CHECK(dev_) << "Unable to open the device at the path: " << device_path;

  Frame challenge;
  challenge.cid = kIdBroadcast;
  challenge.init.cmd = kCtapHidInit;
  challenge.init.bcnth = 0;
  challenge.init.bcntl = kInitNonceSize;
  memset(challenge.init.data, 0xEE, sizeof(challenge.init.data));
  for (size_t i = 0; i < kInitNonceSize; ++i) {
    // This random number generator is seeded, to make tests deterministic.
    challenge.init.data[i] = rand_r(&seed_);
  }

  OK_OR_RETURN(SendFrame(&challenge));

  for (;;) {
    Frame response;
    OK_OR_RETURN(ReceiveFrame(kReceiveTimeout, &response));

    if (response.cid != challenge.cid ||
        response.init.cmd != challenge.init.cmd ||
        response.PayloadLength() != kInitRespSize ||
        memcmp(response.init.data, challenge.init.data, kInitNonceSize)) {
      continue;
    }

    cid_ = (static_cast<uint32_t>(response.init.data[8]) << 24) |
           (static_cast<uint32_t>(response.init.data[9]) << 16) |
           (static_cast<uint32_t>(response.init.data[10]) << 8) |
           (static_cast<uint32_t>(response.init.data[11]) << 0);

    bool has_wink = response.init.data[16] & kWinkCapabilityMask;
    bool has_cbor = response.init.data[16] & kCborCapabilityMask;
    // The negation is intended, because this is a negative feature flag.
    bool has_msg = !(response.init.data[16] & kNmsgCapabilityMask);
    tracker_->SetCapabilities(has_wink, has_cbor, has_msg);
    break;
  }
  return Status::kErrNone;
}

Status HidDevice::Wink() {
  uint8_t cmd = kCtapHidWink;
  OK_OR_RETURN(SendCommand(cmd, std::vector<uint8_t>()));

  std::vector<uint8_t> recv_data;
  Status status = ReceiveCommand(kReceiveTimeout, &cmd, &recv_data);
  if (cmd != kCtapHidWink) return Status::kErrInvalidCommand;
  if (!recv_data.empty()) return Status::kErrInvalidLength;
  return status;
}

Status HidDevice::ExchangeCbor(Command command,
                               const std::vector<uint8_t>& payload,
                               bool expect_up_check,
                               std::vector<uint8_t>* response_cbor) const {
  // Construct outgoing message.
  // Make sure status byte + payload fit into the allowed number of frames.
  if (1 + payload.size() > kMaxDataSize) return Status::kErrInvalidLength;
  std::vector<uint8_t> send_data = {static_cast<uint8_t>(command)};
  send_data.insert(send_data.end(), payload.begin(), payload.end());

  uint8_t cmd = kCtapHidCbor;
  OK_OR_RETURN(SendCommand(cmd, send_data));

  std::vector<uint8_t> recv_data;
  OK_OR_RETURN(ReceiveCommand(kReceiveTimeout, &cmd, &recv_data));

  // The answer might also be a keepalive.
  bool has_sent_prompt = false;
  while (cmd == kCtapHidKeepalive) {
    KeepaliveStatus keepalive_response = ProcessKeepalive(recv_data);
    if (keepalive_response == KeepaliveStatus::kStatusError)
      return Status::kErrOther;
    if (keepalive_response == KeepaliveStatus::kStatusUpNeeded &&
        !has_sent_prompt) {
      has_sent_prompt = true;
      if (!tracker_->IsTouchPromptIgnored()) {
        PromptUser();
      }
    }
    OK_OR_RETURN(ReceiveCommand(kReceiveTimeout, &cmd, &recv_data));
  }

  if (cmd != kCtapHidCbor) return Status::kErrInvalidCommand;
  if (recv_data.empty()) return Status::kErrInvalidLength;

  response_cbor->insert(response_cbor->end(), recv_data.begin() + 1,
                        recv_data.end());

  if (has_sent_prompt && !expect_up_check) {
    tracker_->AddObservation("A prompt was sent unexpectedly.");
  }
  if (!has_sent_prompt && expect_up_check) {
    tracker_->AddObservation(
        "A prompt was expected, but not performed. Sometimes it is just not "
        "recognized if performed too fast.");
  }

  return ByteToStatus(recv_data[0]);
}

KeepaliveStatus HidDevice::ProcessKeepalive(
    const std::vector<uint8_t>& data) const {
  if (data.size() != 1) return KeepaliveStatus::kStatusError;
  if (data[0] == static_cast<uint8_t>(KeepaliveStatus::kStatusProcessing)) {
    Log("received packet for keepalive, key is still processing");
    return KeepaliveStatus::kStatusProcessing;
  }
  if (data[0] == static_cast<uint8_t>(KeepaliveStatus::kStatusUpNeeded)) {
    Log("received packet for keepalive, user interaction is needed");
    return KeepaliveStatus::kStatusUpNeeded;
  }
  return KeepaliveStatus::kStatusError;
}

Status HidDevice::SendCommand(uint8_t cmd,
                              const std::vector<uint8_t>& data) const {
  size_t remaining_data_size = data.size();
  Frame frame;
  frame.cid = cid_;
  frame.init.cmd = Frame::kTypeInitMask | cmd;
  frame.init.bcnth = (remaining_data_size >> 8) & 255;
  frame.init.bcntl = (remaining_data_size & 255);
  int frame_len = std::min(data.size(), sizeof(frame.init.data));
  memset(frame.init.data, 0xEE, sizeof(frame.init.data));
  auto data_it = data.begin();
  std::copy_n(data_it, frame_len, frame.init.data);

  uint8_t seq = 0;
  do {
    OK_OR_RETURN(SendFrame(&frame));

    remaining_data_size -= frame_len;
    data_it += frame_len;

    frame.cont.seq = seq++;
    frame_len = std::min(remaining_data_size, sizeof(frame.cont.data));
    memset(frame.cont.data, 0xEE, sizeof(frame.cont.data));
    std::copy_n(data_it, frame_len, frame.cont.data);
  } while (remaining_data_size);

  return Status::kErrNone;
}

Status HidDevice::ReceiveCommand(absl::Duration timeout, uint8_t* cmd,
                                 std::vector<uint8_t>* data) const {
  data->clear();
  absl::Time end_time = absl::Now() + timeout;

  Frame frame;
  do {
    OK_OR_RETURN(ReceiveFrame(end_time - absl::Now(), &frame));
  } while (frame.cid != cid_ || !frame.IsInitType());

  if (frame.init.cmd == kCtapHidError) return ByteToStatus(frame.init.data[0]);

  *cmd = frame.init.cmd;

  size_t total_len = frame.PayloadLength();
  if (total_len > kMaxDataSize) return Status::kErrInvalidLength;
  data->reserve(total_len);
  size_t frame_len = std::min(sizeof(frame.init.data), total_len);

  data->insert(data->end(), frame.init.data, frame.init.data + frame_len);
  total_len -= frame_len;

  uint8_t seq = 0;
  while (total_len) {
    OK_OR_RETURN(ReceiveFrame(end_time - absl::Now(), &frame));

    if (frame.cid != cid_) continue;
    if (frame.IsInitType()) return Status::kErrInvalidSeq;
    if (frame.MaskedSeq() != seq++) return Status::kErrInvalidSeq;

    frame_len = std::min(sizeof(frame.cont.data), total_len);

    data->insert(data->end(), frame.cont.data, frame.cont.data + frame_len);
    total_len -= frame_len;
  }

  return Status::kErrNone;
}

Status HidDevice::SendFrame(Frame* frame) const {
  uint8_t d[1 + sizeof(Frame)];
  d[0] = 0;                        // un-numbered report
  frame->cid = htonl(frame->cid);  // cid is in network order on the wire
  std::copy_n(reinterpret_cast<uint8_t*>(frame), sizeof(Frame), d + 1);
  frame->cid = ntohl(frame->cid);

  int hidapi_status = hid_write(dev_, d, sizeof(d));
  if (hidapi_status == sizeof(d)) {
    Log(">> send >>", frame);
    return Status::kErrNone;
  }

  return Status::kErrOther;
}

Status HidDevice::ReceiveFrame(absl::Duration timeout, Frame* frame) const {
  if (timeout <= absl::ZeroDuration()) return Status::kErrTimeout;

  int hidapi_status =
      hid_read_timeout(dev_, reinterpret_cast<uint8_t*>(frame), sizeof(Frame),
                       absl::ToInt64Milliseconds(timeout));
  if (hidapi_status == sizeof(Frame)) {
    frame->cid = ntohl(frame->cid);
    Log("<< recv <<", frame);
    return Status::kErrNone;
  }

  if (hidapi_status == -1) return Status::kErrOther;

  Log("timeout");
  return Status::kErrTimeout;
}

void HidDevice::Log(std::string_view message) const {
  if (verbose_logging_) {
    std::cout << message << std::endl;
  }
}

void HidDevice::Log(std::string_view direction, Frame* frame) const {
  if (!verbose_logging_) {
    return;
  }
  std::cout << direction << " "
            << absl::StrCat(absl::Hex(frame->cid, absl::kZeroPad8)) << ":";
  if (frame->IsInitType()) {
    std::cout << absl::StrCat(absl::Hex(frame->type, absl::kZeroPad2));
    std::cout << "[" << frame->PayloadLength() << "]:";
    for (size_t i = 0; i < sizeof(frame->init.data); ++i) {
      std::cout << absl::StrCat(
          absl::Hex(frame->init.data[i], absl::kZeroPad2));
    }
  } else {
    std::cout << "seq=" << absl::StrCat(absl::Hex(frame->type, absl::kZeroPad2))
              << ":";
    for (size_t i = 0; i < sizeof(frame->cont.data); ++i) {
      std::cout << absl::StrCat(
          absl::Hex(frame->cont.data[i], absl::kZeroPad2));
    }
  }
  std::cout << std::endl;
}

std::string HidDevice::FindDevicePath() {
  hid_device_info* devs = nullptr;
  for (int i = 0; i < kHidDeviceRetries && !devs; i++) {
    // Linear increase of waiting time by using the iteration index as a
    // multiplier. This has the nice advantage of not waiting on the first
    // iteration.
    absl::SleepFor(absl::Milliseconds(100) * i);
    devs = hid_enumerate(device_identifiers_.vendor_id,
                         device_identifiers_.product_id);
  }
  hid_device_info* root = devs;
  while (devs && devs->usage_page != 0xf1d0) {
    devs = devs->next;
  }
  CHECK(devs) << "The key with the expected vendor & product ID was not found.";
  std::string pathname = devs->path;
  hid_free_enumeration(root);
  CHECK(!pathname.empty()) << "No path found for this device.";
  return pathname;
}

Status HidDevice::ByteToStatus(uint8_t status_byte) const {
  if (IsKnownStatusByte(status_byte)) {
    return Status(status_byte);
  }

  std::string_view error_code_type = "unknown";
  if (status_byte == kCtap2ErrCborParsingRemovedStatus ||
      status_byte == kCtap2ErrInvalidCborTypeRemovedStatus) {
    error_code_type = "deprecated";
  } else if (status_byte >= kCtap2ErrExtensionFirst &&
             status_byte <= kCtap2ErrExtensionLast) {
    error_code_type = "extension specific";
  } else if (status_byte >= kCtap2ErrVendorFirst &&
             status_byte <= kCtap2ErrVendorLast) {
    error_code_type = "vendor specific";
  }

  tracker_->AddObservation(
      absl::StrCat("Received ", error_code_type, " error code `0x",
                   absl::Hex(status_byte, absl::kZeroPad2), "`"));
  return Status::kErrOther;
}

void PrintFidoDevices() {
  hid_device_info* devs = hid_enumerate(0, 0);  // 0 means all devices.
  for (hid_device_info* cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
    if (cur_dev->usage_page == 0xf1d0 /* FIDO specific usage page*/) {
      std::cout << "Found device" << std::endl;
      std::cout << "  VID/PID     : "
                << absl::StrCat(absl::Hex(cur_dev->vendor_id, absl::kZeroPad4),
                                ":",
                                absl::Hex(cur_dev->product_id, absl::kZeroPad4))
                << std::endl;
      std::cout << "  Page/Usage  : "
                << "0x"
                << absl::StrCat(absl::Hex(cur_dev->usage_page, absl::kZeroPad4))
                << "/0x"
                << absl::StrCat(absl::Hex(cur_dev->usage, absl::kZeroPad4))
                << " (" << cur_dev->usage_page << "/" << cur_dev->usage << ")"
                << std::endl;
      std::cout << "  Manufacturer: ";
      std::wcout << cur_dev->manufacturer_string;
      std::cout << std::endl << "  Product     : ";
      std::wcout << cur_dev->product_string;
      std::cout << std::endl << "  S/N         : ";
      std::wcout << cur_dev->serial_number;
      std::cout << std::endl
                << "  Path        : " << cur_dev->path << std::endl;
      std::cout << std::endl;
    }
  }
  hid_free_enumeration(devs);
}

std::string FindFirstFidoDevicePath() {
  hid_device_info* devs = hid_enumerate(0, 0);  // 0 means all devices.
  std::string device_path;
  for (hid_device_info* cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
    if (cur_dev->usage_page == 0xf1d0 /* FIDO specific usage page*/) {
      device_path = cur_dev->path;
      break;
    }
  }
  hid_free_enumeration(devs);
  return device_path;
}

}  // namespace hid
}  // namespace fido2_tests

