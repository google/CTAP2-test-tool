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

namespace rsp {

std::string RSPPacket::DataToString() const {
  switch (data_) {
    case RSPPacket::Continue:
      return "c";
    default:
      return "";
  }
}

std::string RSPPacket::ToString() const {
  std::stringstream ss;
  ss << "$" << DataToString() << "#" << std::hex
     << static_cast<int>(Checksum());
  return ss.str();
}

uint8_t RSPPacket::Checksum() const {
  uint8_t sum = 0;
  std::string packet = DataToString();
  for (char c : packet) {
    sum += static_cast<uint8_t>(c);
  }
  return sum;
}

}  // namespace rsp