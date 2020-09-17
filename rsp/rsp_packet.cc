// Copyright 2019 Google LLC
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

#include "rsp_packet.h"

#include <sstream>
#include <string>

#include "absl/strings/str_cat.h"

namespace rsp {

std::string RspPacket::DataToString() const {
  switch (data_) {
    case RspPacket::Continue:
      return "c";
    case RspPacket::RequestSupported:
      return "qSupported";
    default:
      return "";
  }
}

std::string RspPacket::ToString() const {
  return absl::StrCat("$", DataToString(), "#",
                      absl::Hex(Checksum(), absl::kZeroPad2));
}

uint8_t RspPacket::Checksum() const {
  uint8_t sum = 0;
  std::string packet = DataToString();
  for (char c : packet) {
    sum += static_cast<uint8_t>(c);
  }
  return sum;
}

}  // namespace rsp