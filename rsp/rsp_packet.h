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

#ifndef GDB_RSP_PACKET_H_
#define GDB_RSP_PACKET_H_

#include <string>

namespace rsp {

// Represents a RSP packet specified in
// https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html#Overview.
class RspPacket {
 public:
  enum PacketData { Continue, RequestSupported };
  RspPacket() = default;
  ~RspPacket() = default;
  RspPacket(PacketData data) : data_(data) {}
  // Allows switch and comparisons of RspPacket class as an enum.
  operator PacketData() const { return data_; }
  bool operator==(RspPacket other) const { return data_ == other.data_; }
  // Returns the string representation of the packet data.
  std::string DataToString() const;
  // Returns the string representation of the packet.
  std::string ToString() const;

 private:
  // Returns the checksum of the packet data.
  uint8_t Checksum() const;
  PacketData data_;
};

}  // namespace rsp

#endif  // GDB_RSP_PACKET_H_