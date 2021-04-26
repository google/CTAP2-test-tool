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

#ifndef GDB_RSP_PACKET_H_
#define GDB_RSP_PACKET_H_

#include <string>

namespace fido2_tests {
namespace rsp {

// Represents a subset of RSP packets specified in
// https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Overview.
class RspPacket {
 public:
  enum PacketData {
    Continue,
    RequestSupported,
    ReadGeneralRegisters,
    ReadFromMemory
  };
  // Constructor for a single packet.
  RspPacket(PacketData data);
  // Constructor for a RSP packet which requires an address and a third integer
  // parameter.
  // address: Hexadecimal representation of the address without leading 0x.
  // param: Depending on the specific packet, the parameter can be
  // interpreted as length, number or cycles, etc.
  RspPacket(PacketData data, const std::string_view& address, int param);
  // Allows switch and comparisons of RspPacket class as an enum.
  operator PacketData() const { return data_; }
  bool operator==(RspPacket other) const { return data_ == other.data_; }
  // Returns the string representation of the packet data.
  std::string DataToString() const;
  // Returns the string representation of the entire packet.
  std::string ToString() const;

 private:
  PacketData data_;
  std::string_view address_;
  int param_;
};

}  // namespace rsp
}  // namespace fido2_tests

#endif  // GDB_RSP_PACKET_H_

