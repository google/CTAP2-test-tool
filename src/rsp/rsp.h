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

#ifndef GDB_RSP_H_
#define GDB_RSP_H_

#include <optional>
#include <vector>

#include "src/rsp/rsp_packet.h"

namespace fido2_tests {
namespace rsp {

// Implements a GDB Remote Serial Protocol (RSP) client through
// TCP socket connection. The protocol documentation can be found here:
// https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html#Remote-Protocol
// Example:
//  rsp::RemoteSerialProtocol rsp;
//  rsp.Initialize();
//  rsp.Connect(port);
//  if (!rsp.SendPacket(rsp::RspPacket::Continue)) { ... }
//  if (rsp.ReceivePacket()) { ... }
//  rsp.Terminate();
class RemoteSerialProtocol {
 public:
  RemoteSerialProtocol();
  // Initializes the socket for serial connection via TCP and
  // allocates memory for incoming packets.
  bool Initialize();
  // Connects the socket to a RSP server listening on a specified port.
  bool Connect(int port);
  // Ends connection and cleans up allocated memory.
  bool Terminate();
  // Sends a RSP packet over the socket with a number of retries.
  bool SendPacket(RspPacket packet, int retries = 1);
  // Receives and returns a RSP reply packet over the socket.
  std::optional<std::string> ReceivePacket();
  // Sends a RSP packet with retry and returns the received reply if any.
  std::optional<std::string> SendRecvPacket(RspPacket packet, int retries = 1);

 private:
  // Non-blockingly receives at most receive_length bytes of data.
  // Returns whether there was data available and the actual content received.
  std::optional<std::string> Receive(int receive_length);
  // Reads acknowledgement packet and returns whether the packet
  // was acknowledged.
  bool ReadAcknowledgement();

  int socket_ = -1;
  std::vector<char> recv_buffer_;
};

}  // namespace rsp
}  // namespace fido2_tests

#endif  // GDB_RSP_H_

