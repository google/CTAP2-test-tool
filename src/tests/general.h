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

#ifndef TESTS_GENERAL_H_
#define TESTS_GENERAL_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/tests/base.h"

namespace fido2_tests {

// Tests if the Wink response matches the capability bit.
TEST_CLASS(WinkTest);

// Checks if the GetInfo command has valid output implicitly. Also checks for
// support of PIN protocol version 1, because it is used throughout all tests.
TEST_CLASS(GetInfoTest);

// Tests if credentials persist after replugging.
TEST_CLASS(PersistentCredentialsTest);

// Tests if PIN retries persist after replugging.
TEST_CLASS(PersistentPinRetriesTest);

// Tests if the auth token regenerates after replugging.
TEST_CLASS(RegeneratesPinAuthTest);

}  // namespace fido2_tests

#endif  // TESTS_GENERAL_H_

