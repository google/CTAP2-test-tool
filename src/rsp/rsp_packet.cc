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

#include "src/rsp/rsp_packet.h"

#include <sstream>
#include <string>

#include "absl/strings/str_cat.h"

namespace fido2_tests {
namespace rsp {
namespace {

// Returns the checksum of the packet data.
uint8_t Checksum(const std::string_view& packet) {
  uint8_t sum = 0;
  for (char c : packet) {
    sum += static_cast<uint8_t>(c);
  }
  return sum;
}

}  // namespace

RspPacket::RspPacket(PacketData data) : data_(data) {}

RspPacket::RspPacket(PacketData data, const std::string_view& address,
                     int param)
    : data_(data), address_(address), param_(param) {}

std::string RspPacket::DataToString() const {
  switch (data_) {
    case RspPacket::Continue:
      return "c";
    case RspPacket::ReadFromMemory:
      return absl::StrCat("m", address_, ",", param_);
    case RspPacket::ReadGeneralRegisters:
      return "g";
    case RspPacket::RequestSupported:
      return "qSupported";
    default:
      return "";
  }
}

std::string RspPacket::ToString() const {
  std::string packet_data = DataToString();
  return absl::StrCat("$", packet_data, "#",
                      absl::Hex(Checksum(packet_data), absl::kZeroPad2));
}

}  // namespace rsp
}  // namespace fido2_tests

