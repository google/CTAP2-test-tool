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

#ifndef TESTS_RESET_H_
#define TESTS_RESET_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/tests/base.h"

namespace fido2_tests {

// Tests if credentials on the device are wiped out after reset.
TEST_CLASS(DeleteCredentialsTest);

// Tests if a PIN on the device is wiped out after reset.
TEST_CLASS(DeletePinTest);

// Tests if requirements for resetting are enforced.
TEST_CLASS(ResetPhysicalPresenceTest);

}  // namespace fido2_tests

#endif  // TESTS_RESET_H_

