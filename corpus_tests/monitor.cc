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

#include "corpus_tests/monitor.h"

namespace corpus_tests {

bool Monitor::Attach(fido2_tests::DeviceInterface* device, int port) {
  device_ = device;
  if (!rsp_client_.Initialize()) {
    return false;
  }
  return rsp_client_.Connect(port);
}

bool Monitor::Start() {
  return rsp_client_.SendPacket(rsp::RspPacket(rsp::RspPacket::Continue));
}

bool Monitor::DeviceCrashed() { return rsp_client_.ReceivePacket(); }

}  // namespace corpus_tests