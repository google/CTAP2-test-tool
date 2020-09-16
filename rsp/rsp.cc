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

#include "rsp_packet.h"

namespace rsp {

// Timeout = 0.5 seconds.
const int kReceiveTimeoutMicroSec = 500000;
// No specification found about max length, assuming 1024 is enough.
const int kReceiveBufferLength = 1024;

RSP::RSP() {}

RSP::~RSP() {}

bool RSP::Initialize() {
  recv_buffer_ = (char*)malloc(kReceiveBufferLength * sizeof(char));
  return ((socket_ = socket(AF_INET, SOCK_STREAM, 0)) != -1);
}

bool RSP::Connect(int port) {
  if (socket_ < 0) {
    return false;
  }
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
    return false;
  }
  return (connect(socket_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) !=
          -1);
}

bool RSP::Terminate() {
  free(recv_buffer_);
  return (close(socket_) != -1);
}

bool RSP::SendPacket(RSPPacket packet) {
  char const* buf = packet.ToString().c_str();
  if (send(socket_, buf, strlen(buf), 0) == -1) {
    return false;
  }
  return ReadAcknowledgement();
}

// The possible reply packets are listed in:
// https://sourceware.org/gdb/current/onlinedocs/gdb/Stop-Reply-Packets.html#Stop-Reply-Packets
bool RSP::ReceivePacket() {
  if (Receive(kReceiveBufferLength)) {
    return true;
  }
  return false;
}

bool RSP::Receive(int receive_length) {
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
  recv(socket_, recv_buffer_, receive_length, 0);
  return true;
}

// Acknowledgement is either '+' or '-'
bool RSP::ReadAcknowledgement() {
  if (!Receive(1)) {
    return false;
  }
  return recv_buffer_[0] == '+';
}

}  // namespace rsp