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

#include <iostream>

#include "gtest/gtest.h"

namespace fido2_tests {
namespace rsp {
namespace {

TEST(RspPacket, TestEqual) {
  RspPacket cont_packet_1(RspPacket::Continue);
  RspPacket cont_packet_2(RspPacket::Continue);
  RspPacket request_packet_1(RspPacket::RequestSupported);
  RspPacket request_packet_2(RspPacket::RequestSupported);
  EXPECT_TRUE(cont_packet_1 == cont_packet_2);
  EXPECT_TRUE(request_packet_1 == request_packet_2);
  EXPECT_FALSE(cont_packet_1 == request_packet_1);
}

TEST(RspPacket, TestDataString) {
  RspPacket packet(RspPacket::Continue);
  EXPECT_EQ(packet.DataToString(), "c");
  packet = RspPacket(RspPacket::RequestSupported);
  EXPECT_EQ(packet.DataToString(), "qSupported");
  packet = RspPacket(RspPacket::ReadGeneralRegisters);
  EXPECT_EQ(packet.DataToString(), "g");
  packet = RspPacket(RspPacket::ReadFromMemory, "00000000", 0);
  EXPECT_EQ(packet.DataToString(), "m00000000,0");
  packet = RspPacket(RspPacket::ReadFromMemory, "e000ed2c", 4);
  EXPECT_EQ(packet.DataToString(), "me000ed2c,4");
  packet = RspPacket(RspPacket::ReadFromMemory, "", 100);
  EXPECT_EQ(packet.DataToString(), "m,100");
}

TEST(RspPacket, TestToString) {
  RspPacket packet(RspPacket::Continue);
  EXPECT_EQ(packet.ToString(), "$c#63");
  packet = RspPacket(RspPacket::RequestSupported);
  EXPECT_EQ(packet.ToString(), "$qSupported#37");
  packet = RspPacket(RspPacket::ReadGeneralRegisters);
  EXPECT_EQ(packet.ToString(), "$g#67");
  packet = RspPacket(RspPacket::ReadFromMemory, "00000000", 0);
  EXPECT_EQ(packet.ToString(), "$m00000000,0#49");
  packet = RspPacket(RspPacket::ReadFromMemory, "e000ed2c", 4);
  EXPECT_EQ(packet.ToString(), "$me000ed2c,4#20");
  packet = RspPacket(RspPacket::ReadFromMemory, "", 100);
  EXPECT_EQ(packet.ToString(), "$m,100#2a");
}

}  // namespace
}  // namespace rsp
}  // namespace fido2_tests

