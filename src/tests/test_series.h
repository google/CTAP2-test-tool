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

#ifndef TESTS_TEST_SERIES_H_
#define TESTS_TEST_SERIES_H_

#include <cstdio>

#include "absl/types/variant.h"
#include "src/cbor_builders.h"
#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// Contains tests for commands and input parameters. Commands tests usually
// check all specified steps, and how the device acts then deviating from these
// steps.
// Input parameter tests strictly enforce correct type of parameters, including
// members of maps and arrays. It is strict at checking unexpected additional
// parameters, whenever the specification does not explicitly allow them.
// In general, tests can also report observations or problems as side effects.
// Example:
//    fido2_tests::TestSeries test_series = fido2_tests::TestSeries();
//    test_series.GetInfoTest(device, device_tracker, command_state);
class TestSeries {
 public:
  // Tests for MakeCredential.

  // Check if MakeCredential accepts different CBOR types for its parameters.
  void MakeCredentialBadParameterTypesTest(DeviceInterface* device,
                                           DeviceTracker* device_tracker,
                                           CommandState* command_state);
  // Check if MakeCredential accepts leaving out one of the required parameters.
  void MakeCredentialMissingParameterTest(DeviceInterface* device,
                                          DeviceTracker* device_tracker,
                                          CommandState* command_state);
  // Check the optional map entries of the relying party entity.
  void MakeCredentialRelyingPartyEntityTest(DeviceInterface* device,
                                            DeviceTracker* device_tracker,
                                            CommandState* command_state);
  // Check the optional map entries of the user entity.
  void MakeCredentialUserEntityTest(DeviceInterface* device,
                                    DeviceTracker* device_tracker,
                                    CommandState* command_state);
  // Check the inner array transport elements of the exclude list.
  void MakeCredentialExcludeListCredentialDescriptorTest(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state);
  // Check if unknown extensions are accepted.
  void MakeCredentialExtensionsTest(DeviceInterface* device,
                                    DeviceTracker* device_tracker,
                                    CommandState* command_state);
  // Tests if the authenticator checks the exclude list properly.
  void MakeCredentialExcludeListTest(DeviceInterface* device,
                                     DeviceTracker* device_tracker,
                                     CommandState* command_state);
  // Tests correct behavior with different COSE algorithms. Tests non-existing
  // algorithm identifier and type.
  void MakeCredentialCoseAlgorithmTest(DeviceInterface* device,
                                       DeviceTracker* device_tracker,
                                       CommandState* command_state);
  // Tests correct behavior when setting rk, up and uv.
  void MakeCredentialOptionsTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state);
  // Tests if the PIN is correctly enforced. Resets afterwards to unset the PIN.
  void MakeCredentialPinAuthTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state);
  // Tests correct behavior when creating multiple keys. This test attempts to
  // create num_credentials credentials, stopping before that if the internal
  // key store is full. It resets afterwards to clear the storage.
  void MakeCredentialMultipleKeysTest(DeviceInterface* device,
                                      DeviceTracker* device_tracker,
                                      CommandState* command_state,
                                      int num_credentials);
  // Tests if the key hardware actually interacts with a user. This test can not
  // be performed automatically, but requires tester feedback.
  void MakeCredentialPhysicalPresenceTest(DeviceInterface* device,
                                          DeviceTracker* device_tracker,
                                          CommandState* command_state);
  // Tests if the user name is resistent to long inputs and bad UTF8.
  void MakeCredentialDisplayNameEncodingTest(DeviceInterface* device,
                                             DeviceTracker* device_tracker,
                                             CommandState* command_state);
  // Tests if the HMAC-secret extension works properly.
  void MakeCredentialHmacSecretTest(DeviceInterface* device,
                                    DeviceTracker* device_tracker,
                                    CommandState* command_state);

  // Tests for GetAssertion.

  // Check if GetAssertion accepts different CBOR types for its parameters.
  void GetAssertionBadParameterTypesTest(DeviceInterface* device,
                                         DeviceTracker* device_tracker,
                                         CommandState* command_state);
  // Check if GetAssertion accepts leaving out one of the required parameters.
  void GetAssertionMissingParameterTest(DeviceInterface* device,
                                        DeviceTracker* device_tracker,
                                        CommandState* command_state);
  // Check the inner array transport elements of the allow list.
  void GetAssertionAllowListCredentialDescriptorTest(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state);
  // Check if unknown extensions are accepted.
  void GetAssertionExtensionsTest(DeviceInterface* device,
                                  DeviceTracker* device_tracker,
                                  CommandState* command_state);
  // Tests correct behavior when setting rk, up and uv.
  void GetAssertionOptionsTest(DeviceInterface* device,
                               DeviceTracker* device_tracker,
                               CommandState* command_state);
  // Tests correct differentiation between residential and non-residential.
  void GetAssertionResidentialKeyTest(DeviceInterface* device,
                                      DeviceTracker* device_tracker,
                                      CommandState* command_state);
  // Tests if the PIN is correctly enforced. Resets afterwards to unset the PIN.
  void GetAssertionPinAuthTest(DeviceInterface* device,
                               DeviceTracker* device_tracker,
                               CommandState* command_state);
  // Tests if the key hardware actually interacts with a user. This test can not
  // be performed automatically, but requires tester feedback.
  void GetAssertionPhysicalPresenceTest(DeviceInterface* device,
                                        DeviceTracker* device_tracker,
                                        CommandState* command_state);

  // TODO(kaczmarczyck) Tests for GetNextAssertion.

  // Tests for GetInfo.

  // Checks if the GetInfo command has valid output implicitly. Also checks for
  // support of PIN protocol version 1, because it is used throughout all tests.
  void GetInfoTest(DeviceInterface* device, DeviceTracker* device_tracker,
                   CommandState* command_state);

  // Tests for ClientPin.

  // Check the input parameters of the client PIN subcommand getPinRetries.
  void ClientPinGetPinRetriesTest(DeviceInterface* device,
                                  DeviceTracker* device_tracker,
                                  CommandState* command_state);
  // Check the input parameters of the client PIN subcommand getKeyAgreement.
  void ClientPinGetKeyAgreementTest(DeviceInterface* device,
                                    DeviceTracker* device_tracker,
                                    CommandState* command_state);
  // Check the input parameters of the client PIN subcommand setPin.
  void ClientPinSetPinTest(DeviceInterface* device,
                           DeviceTracker* device_tracker,
                           CommandState* command_state);
  // Check the input parameters of the client PIN subcommand changePin.
  void ClientPinChangePinTest(DeviceInterface* device,
                              DeviceTracker* device_tracker,
                              CommandState* command_state);
  // Check the input parameters of the client PIN subcommand
  // getPinUvAuthTokenUsingPin.
  void ClientPinGetPinUvAuthTokenUsingPinTest(DeviceInterface* device,
                                              DeviceTracker* device_tracker,
                                              CommandState* command_state);
  // Check the input parameters of the client PIN subcommand
  // getPinUvAuthTokenUsingUv. Requires CTAP 2.1, returns otherwise.
  void ClientPinGetPinUvAuthTokenUsingUvTest(DeviceInterface* device,
                                             DeviceTracker* device_tracker,
                                             CommandState* command_state);
  // Check the input parameters of the client PIN subcommand getUVRetries.
  // Requires CTAP 2.1, returns otherwise.
  void ClientPinGetUVRetriesTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state);
  // Tests if the PIN minimum and maximum length are enforced correctly for the
  // SetPin and ChangePin command. Resets the device on failed tests so that the
  // following test will still find a valid state. Might end with the device
  // having a PIN set.
  void ClientPinRequirementsTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state);
  // Tests PIN protocol requirements introduced in CTAP 2.1. This includes
  // testing different padding lengths for SetPin and ChangePin. Resets the
  // device before tests and on failed tests. Might end with the device having a
  // PIN set.
  void ClientPinRequirements2Point1Test(DeviceInterface* device,
                                        DeviceTracker* device_tracker,
                                        CommandState* command_state);
  // Tests if retries decrement properly and respond with correct error codes.
  // Creates a PIN if necessary. Resets the device at the beginning and the end.
  void ClientPinRetriesTest(DeviceInterface* device,
                            DeviceTracker* device_tracker,
                            CommandState* command_state);

  // Tests for Reset.

  // Tests if the state on the device is wiped out.
  // Replugging the device before calling the function is necessary.
  void ResetDeletionTest(DeviceInterface* device, DeviceTracker* device_tracker,
                         CommandState* command_state);
  // Tests if requirements for resetting are enforced.
  void ResetPhysicalPresenceTest(DeviceInterface* device,
                                 DeviceTracker* device_tracker,
                                 CommandState* command_state);
  // Tests if the state is persistent when being replugged. This includes
  // credentials and the PIN retries.
  void PersistenceTest(DeviceInterface* device, DeviceTracker* device_tracker,
                       CommandState* command_state);
};

namespace test_helpers {

// Returns a PIN that is different from the PIN set on the device. This is
// enforced in SetPin() by making sure the chosen PIN is different.
cbor::Value::BinaryValue BadPin();

// Extracts the credential ID from an authenticator data structure[1].
// [1] https://www.w3.org/TR/webauthn/#sec-authenticator-data
cbor::Value::BinaryValue ExtractCredentialId(const cbor::Value& response);

// Extracts the PIN retries from an authenticator client PIN response.
int ExtractPinRetries(const cbor::Value& response);

void PrintByteVector(const cbor::Value::BinaryValue& vec);

void PrintNoTouchPrompt();

// TODO(#16) replace version string with FIDO_2_1 when specification is final
bool IsFido2Point1Complicant(DeviceTracker* device_tracker);

// Makes a credential for all tests that require one, for example assertions.
cbor::Value MakeTestCredential(DeviceTracker* device_tracker,
                               CommandState* command_state,
                               const std::string& rp_id,
                               bool use_residential_key);

// The following helper functions are used to test input parameters.

// Tries to insert types other than the correct one into the CBOR builder.
// Make sure to pass the appropriate CborBuilder for your command. The correct
// types are inferred through the currently present builder entries. The tests
// include other types than maps for the command and inner types of maps and
// the first element of an inner array (assuming all array elements have the
// same type). If that first element happens to be a map, its entries are also
// checked. Even though this seems like an arbitrary choice at first, it
// covers most of the CTAP input.
void TestBadParameterTypes(DeviceInterface* device,
                           DeviceTracker* device_tracker, Command command,
                           CborBuilder* builder);
// Tries to remove each parameter once. Make sure to pass the appropriate
// CborBuilder for your command. The necessary parameters are inferred through
// the currently present builder entries.
void TestMissingParameters(DeviceInterface* device,
                           DeviceTracker* device_tracker, Command command,
                           CborBuilder* builder);
// Tries to insert types other than the correct one into map entries. Those
// maps themselves are values of the command parameter map. If
// has_wrapping_array is true, the inner map is used as an array element
// instead. To sum it up, the data structure tested can look like this:
// command:outer_map_key->inner_map[key]->wrongly_typed_value or
// command:outer_map_key->[inner_map[key]->wrongly_typed_value].
void TestBadParametersInInnerMap(DeviceInterface* device,
                                 DeviceTracker* device_tracker, Command command,
                                 CborBuilder* builder, int outer_map_key,
                                 const cbor::Value::MapValue& inner_map,
                                 bool has_wrapping_array);
// Tries to insert types other than the correct one into array elements. Those
// arrays themselves are values of the command parameter map.
void TestBadParametersInInnerArray(DeviceInterface* device,
                                   DeviceTracker* device_tracker,
                                   Command command, CborBuilder* builder,
                                   int outer_map_key,
                                   const cbor::Value& array_element);
// Tries to insert a map or an array as a transport in an array of public key
// credential descriptors. Both excludeList in MakeCredential and allowList in
// GetAssertion expect this kind of value and share this test. Authenticators
// must ignore unknown items in the transports list, so unexpected types are
// untested. For arrays and maps though, the maximum nesting depth is reached.
void TestCredentialDescriptorsArrayForCborDepth(
    DeviceInterface* device, DeviceTracker* device_tracker, Command command,
    CborBuilder* builder, int map_key, const std::string& rp_id);

// The following helper functions are used to test command behaviour.

// Gets and checks the PIN retry counter response from the authenticator.
int GetPinRetries(DeviceInterface* device, DeviceTracker* device_tracker);
// Checks if the PIN we currently assume is set works for getting an auth
// token. This way, we don't have to trust only the returned status code
// after a SetPin or ChangePin command. It does not actually return an auth
// token, use GetAuthToken() in that case.
void CheckPinByGetAuthToken(DeviceTracker* device_tracker,
                            CommandState* command_state);
// Checks if the PIN is not currently set by trying to make a credential.
// The MakeCredential command should fail when the authenticator is PIN
// protected. Even though this test could fail in case of a bad implementation
// of Make Credential, this kind of misbehavior would be caught in another
// test.
void CheckPinAbsenceByMakeCredential(DeviceInterface* device,
                                     DeviceTracker* device_tracker);

}  // namespace test_helpers

}  // namespace fido2_tests

#endif  // TESTS_TEST_SERIES_H_
