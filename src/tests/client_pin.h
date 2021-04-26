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

#ifndef TESTS_CLIENT_PIN_H_
#define TESTS_CLIENT_PIN_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/tests/base.h"

namespace fido2_tests {

// Tests if GetPinRetries works with parameters of the wrong type.
TEST_CLASS(GetPinRetriesBadParameterTypesTest);

// Tests if GetPinRetries works with missing parameters.
TEST_CLASS(GetPinRetriesMissingParameterTest);

// Tests if GetKeyAgreement works with parameters of the wrong type.
TEST_CLASS(GetKeyAgreementBadParameterTypesTest);

// Tests if GetKeyAgreement works with missing parameters.
TEST_CLASS(GetKeyAgreementMissingParameterTest);

// Tests if SetPin works with parameters of the wrong type.
TEST_CLASS(SetPinBadParameterTypesTest);

// Tests if SetPin works with missing parameters.
TEST_CLASS(SetPinMissingParameterTest);

// Tests if ChangePin works with parameters of the wrong type.
TEST_CLASS(ChangePinBadParameterTypesTest);

// Tests if ChangePin works with missing parameters.
TEST_CLASS(ChangePinMissingParameterTest);

// Tests if GetPinToken works with parameters of the wrong type.
TEST_CLASS(GetPinTokenBadParameterTypesTest);

// Tests if GetPinToken works with missing parameters.
TEST_CLASS(GetPinTokenMissingParameterTest);

// Tests if GetPinUvAuthTokenUsingUvWithPermissions works with parameters of the
// wrong type.
TEST_CLASS(GetPinUvAuthTokenUsingUvWithPermissionsBadParameterTypesTest);

// Tests if GetPinUvAuthTokenUsingUvWithPermissions works with missing
// parameters.
TEST_CLASS(GetPinUvAuthTokenUsingUvWithPermissionsMissingParameterTest);

// Tests if GetUVRetries works with parameters of the wrong type.
TEST_CLASS(GetUVRetriesBadParameterTypesTest);

// Tests if GetUVRetries works with missing parameters.
TEST_CLASS(GetUVRetriesMissingParameterTest);

// Tests if PIN requirement are enforced in SetPin.
TEST_CLASS(ClientPinRequirementsSetPinTest);

// Tests if PIN requirement are enforced in ChangePin.
TEST_CLASS(ClientPinRequirementsChangePinTest);

// Tests if new PIN requirement are enforced in SetPin.
TEST_CLASS(ClientPinNewRequirementsSetPinTest);

// Tests if new PIN requirement are enforced in ChangePin.
TEST_CLASS(ClientPinNewRequirementsChangePinTest);

// Tests if key material is regenerated correctly.
TEST_CLASS(ClientPinOldKeyMaterialTest);

// Tests if PIN retries are decreased and reset.
TEST_CLASS(ClientPinGeneralPinRetriesTest);

// Tests if PIN auth attempts are blocked correctly.
TEST_CLASS(ClientPinAuthBlockPinRetriesTest);

// Tests if PINs are blocked correctly.
TEST_CLASS(ClientPinBlockPinRetriesTest);

}  // namespace fido2_tests

#endif  // TESTS_CLIENT_PIN_H_

