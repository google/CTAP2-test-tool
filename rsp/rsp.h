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

#ifndef GDB_RSP_H_
#define GDB_RSP_H_

#include "rsp_packet.h"

namespace rsp {

// Implements a GDB RSP client through TCP socket connection.
class RSP {
 public:
  RSP();
  ~RSP();
  // Initializes the socket for serial connection via TCP and
  // allocates memory for incoming packets.
  bool Initialize();
  // Connects the socket to a RSP server listening on a specified port.
  bool Connect(int port);
  // Ends connection and cleans up allocated memory.
  bool Terminate();
  // Sends a RSP packet over the socket.
  bool SendPacket(RSPPacket packet);
  bool ReceivePacket();

 private:
  // Non-blockingly receives at most receive_length bytes of data.
  bool Receive(int receive_length);
  // Reads acknowledgement packet and returns whether the packet
  // was acknowledged.
  bool ReadAcknowledgement();

  int socket_;
  char* recv_buffer_;
};

}  // namespace rsp

#endif  // GDB_RSP_H_