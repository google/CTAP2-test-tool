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

#ifndef TESTS_TEST_HELPERS_H_
#define TESTS_TEST_HELPERS_H_

#include "src/cbor_builders.h"
#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

namespace test_helpers {

// Returns a PIN of the given length. It is similar to DefaultPin in
// command_state.cc, but differs in suggested usage. The bad PIN is never
// supposed to be successfully set as the device PIN.
cbor::Value::BinaryValue BadPin(size_t pin_length);

// Extracts the credential ID from an authenticator data structure[1].
// [1] https://www.w3.org/TR/webauthn/#sec-authenticator-data
cbor::Value::BinaryValue ExtractCredentialId(const cbor::Value& response);

// Gets and checks the PIN retry counter response from the authenticator.
// Returns the number from the reponse, if successful, or an error message.
absl::variant<int, std::string> GetPinRetries(DeviceInterface* device,
                                              DeviceTracker* device_tracker);

void PrintNoTouchPrompt();

// TODO(#16) replace version string with FIDO_2_1 when specification is final
bool IsFido2Point1Complicant(DeviceTracker* device_tracker);

// The following helper functions are used to test input parameters. All return
// an error message, if a test fails.

// Tries to insert types other than the correct one into the CBOR builder.
// Make sure to pass the appropriate CborBuilder for your command. The correct
// types are inferred through the currently present builder entries. The tests
// include other types than maps for the command and inner types of maps and
// the first element of an inner array (assuming all array elements have the
// same type). If that first element happens to be a map, its entries are also
// checked. Even though this seems like an arbitrary choice, it covers most of
// the CTAP input.
std::optional<std::string> TestBadParameterTypes(DeviceInterface* device,
                                                 DeviceTracker* device_tracker,
                                                 Command command,
                                                 CborBuilder* builder);

// Tries to remove each parameter once. Make sure to pass the appropriate
// CborBuilder for your command. The necessary parameters are inferred through
// the currently present builder entries.
std::optional<std::string> TestMissingParameters(DeviceInterface* device,
                                                 DeviceTracker* device_tracker,
                                                 Command command,
                                                 CborBuilder* builder);

// Tries to insert types other than the correct one into map entries. Those
// maps themselves are values of the command parameter map. If
// has_wrapping_array is true, the inner map is used as an array element
// instead. To sum it up, the data structure tested can look like this:
// command:outer_map_key->inner_map[key]->wrongly_typed_value or
// command:outer_map_key->[inner_map[key]->wrongly_typed_value].
std::optional<std::string> TestBadParametersInInnerMap(
    DeviceInterface* device, DeviceTracker* device_tracker, Command command,
    CborBuilder* builder, int outer_map_key,
    const cbor::Value::MapValue& inner_map, bool has_wrapping_array);

// Tries to insert types other than the correct one into array elements. Those
// arrays themselves are values of the command parameter map.
std::optional<std::string> TestBadParametersInInnerArray(
    DeviceInterface* device, DeviceTracker* device_tracker, Command command,
    CborBuilder* builder, int outer_map_key, const cbor::Value& array_element);

// Returns an optional's string value, if it exists.
#define NONE_OR_RETURN(x)                             \
  do {                                                \
    std::optional<std::string> __error_message = (x); \
    if (__error_message.has_value()) {                \
      return __error_message;                         \
    }                                                 \
  } while (0)

}  // namespace test_helpers
}  // namespace fido2_tests

#endif  // TESTS_TEST_HELPERS_H_

