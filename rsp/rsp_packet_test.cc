// Copyright 2020 Google LLC
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

#include "gtest/gtest.h"

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
}

TEST(RspPacket, TestToString) {
  RspPacket packet(RspPacket::Continue);
  EXPECT_EQ(packet.ToString(), "$c#63");
  packet = RspPacket(RspPacket::RequestSupported);
  EXPECT_EQ(packet.ToString(), "$qSupported#37");
}

}  // namespace
}  // namespace rsp