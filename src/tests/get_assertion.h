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

#ifndef TESTS_GET_ASSERTION_H_
#define TESTS_GET_ASSERTION_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/tests/base.h"

namespace fido2_tests {

// Tests if GetAssertion works with parameters of the wrong type.
TEST_CLASS(GetAssertionBadParameterTypesTest);

// Tests if GetAssertion works with missing parameters.
TEST_CLASS(GetAssertionMissingParameterTest);

// Tests credential descriptors in the allow list of GetAssertion.
TEST_CLASS(GetAssertionAllowListCredentialDescriptorTest);

// Tests if unknown extensions are ignored in GetAssertion.
TEST_CLASS(GetAssertionExtensionsTest);

// Tests if the resident key option is rejected in GetAssertion.
TEST_CLASS(GetAssertionOptionRkTest);

// Tests if the user presence option is supported in GetAssertion.
TEST_CLASS(GetAssertionOptionUpTest);

// Tests if user verification set to false is accepted in GetAssertion.
TEST_CLASS(GetAssertionOptionUvFalseTest);

// Tests is user verification set to true is accepted in GetAssertion.
TEST_CLASS(GetAssertionOptionUvTrueTest);

// Tests if unknown options are ignored in GetAssertion.
TEST_CLASS(GetAssertionOptionUnknownTest);

// Tests if assertions with resident keys work.
TEST_CLASS(GetAssertionResidentKeyTest);

// Tests if assertions with non-resident keys work.
TEST_CLASS(GetAssertionNonResidentKeyTest);

// Tests the response on an empty PIN auth without a PIN in GetAssertion.
TEST_CLASS(GetAssertionPinAuthEmptyTest);

// Tests if the PIN protocol parameter is checked in GetAssertion.
TEST_CLASS(GetAssertionPinAuthProtocolTest);

// Tests if a PIN auth is rejected without a PIN set in GetAssertion.
TEST_CLASS(GetAssertionPinAuthNoPinTest);

// Tests the response on an empty PIN auth with a PIN in GetAssertion.
TEST_CLASS(GetAssertionPinAuthEmptyWithPinTest);

// Tests if the PIN auth is correctly checked with a PIN set in GetAssertion.
TEST_CLASS(GetAssertionPinAuthTest);

// Tests if client PIN fails with missing parameters in GetAssertion.
TEST_CLASS(GetAssertionPinAuthMissingParameterTest);

// Tests if user touch is required for GetAssertion.
TEST_CLASS(GetAssertionPhysicalPresenceTest);

// Tests if empty user IDs are omitted in the response.
TEST_CLASS(GetAssertionEmptyUserIdTest);

}  // namespace fido2_tests

#endif  // TESTS_GET_ASSERTION_H_

