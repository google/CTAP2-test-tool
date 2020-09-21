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

#include "rsp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "rsp_packet.h"

namespace rsp {

// Timeout = 0.5 seconds.
constexpr int kReceiveTimeoutMicroSec = 500000;
// No specification found about max length,
// Using 4000 as nRF52840-dk supported packet size.
constexpr int kReceiveBufferLength = 4000;

RemoteSerialProtocol::RemoteSerialProtocol()
    : recv_buffer_(kReceiveBufferLength) {}

bool RemoteSerialProtocol::Initialize() {
  return ((socket_ = socket(AF_INET, SOCK_STREAM, 0)) != -1);
}

bool RemoteSerialProtocol::Connect(int port) {
  if (socket_ < 0) {
    return false;
  }
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port);
  if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
    return false;
  }
  return (connect(socket_, (struct sockaddr*)&server_address,
                  sizeof(server_address)) != -1);
}

bool RemoteSerialProtocol::Terminate() { return (close(socket_) != -1); }

bool RemoteSerialProtocol::SendPacket(RspPacket packet) {
  char const* buf = packet.ToString().c_str();
  if (send(socket_, buf, strlen(buf), 0) == -1) {
    return false;
  }
  return ReadAcknowledgement();
}

// The possible reply packets are listed in:
// https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
bool RemoteSerialProtocol::ReceivePacket() {
  return Receive(kReceiveBufferLength);
}

bool RemoteSerialProtocol::Receive(int receive_length) {
  fd_set file_set;
  FD_ZERO(&file_set);
  FD_SET(socket_, &file_set);
  struct timeval tv {
    0, kReceiveTimeoutMicroSec
  };
  int return_value = select(socket_ + 1, &file_set, NULL, NULL, &tv);
  if (return_value <= 0) {
    return false;
  }
  recv(socket_, recv_buffer_.data(), receive_length, 0);
  return true;
}

// Acknowledgement is either '+' or '-'
bool RemoteSerialProtocol::ReadAcknowledgement() {
  if (!Receive(1)) {
    return false;
  }
  return recv_buffer_[0] == '+';
}

}  // namespace rsp