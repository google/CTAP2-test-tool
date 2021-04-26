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

#ifndef TESTS_MAKE_CREDENTIAL_H_
#define TESTS_MAKE_CREDENTIAL_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/tests/base.h"

namespace fido2_tests {

// Tests if MakeCredential works with parameters of the wrong type.
TEST_CLASS(MakeCredentialBadParameterTypesTest);

// Tests if MakeCredential works with missing parameters.
TEST_CLASS(MakeCredentialMissingParameterTest);

// Tests bad parameters in RP entity parameter of MakeCredential.
TEST_CLASS(MakeCredentialRelyingPartyEntityTest);

// Tests bad parameters in user parameter of MakeCredential.
TEST_CLASS(MakeCredentialUserEntityTest);

// Tests credential descriptors in the exclude list of MakeCredential.
TEST_CLASS(MakeCredentialExcludeListCredentialDescriptorTest);

// Tests if unknown extensions are ignored in MakeCredential.
TEST_CLASS(MakeCredentialExtensionsTest);

// Tests if the exclude list is used correctly.
TEST_CLASS(MakeCredentialExcludeListTest);

// Tests entries in the credential parameters list.
TEST_CLASS(MakeCredentialCredParamsTest);

// Tests if the resident key option is supported.
TEST_CLASS(MakeCredentialOptionRkTest);

// Tests if user presence set to false is rejected.
TEST_CLASS(MakeCredentialOptionUpFalseTest);

// Tests if user verification set to false is accepted.
TEST_CLASS(MakeCredentialOptionUvFalseTest);

// Tests is user verification set to true is accepted.
TEST_CLASS(MakeCredentialOptionUvTrueTest);

// Tests if unknown options are ignored.
TEST_CLASS(MakeCredentialOptionUnknownTest);

// Tests the response on an empty PIN auth without a PIN.
TEST_CLASS(MakeCredentialPinAuthEmptyTest);

// Tests if the PIN protocol parameter is checked.
TEST_CLASS(MakeCredentialPinAuthProtocolTest);

// Tests if a PIN auth is rejected without a PIN set in MakeCredential.
TEST_CLASS(MakeCredentialPinAuthNoPinTest);

// Tests the response on an empty PIN auth with a PIN.
TEST_CLASS(MakeCredentialPinAuthEmptyWithPinTest);

// Tests the response on an empty PIN auth without a PIN
TEST_CLASS(MakeCredentialPinAuthTest);

// Tests if client PIN fails with missing parameters.
TEST_CLASS(MakeCredentialPinAuthMissingParameterTest);

// Tests if two credentials have the same ID.
TEST_CLASS(MakeCredentialDuplicateTest);

// Tests if storing lots of credentials is handled gracefully.
TEST_CLASS(MakeCredentialFullStoreTest);

// Tests if user touch is required for MakeCredential.
TEST_CLASS(MakeCredentialPhysicalPresenceTest);

// Tests if non-ASCII display name are accepted.
TEST_CLASS(MakeCredentialNonAsciiDisplayNameTest);

// Tests if invalid UTF8 is caught in displayName.
TEST_CLASS(MakeCredentialUtf8DisplayNameTest);

// Tests the HMAC secret extension with MakeCredential.
TEST_CLASS(MakeCredentialHmacSecretTest);

}  // namespace fido2_tests

#endif  // TESTS_MAKE_CREDENTIAL_H_

