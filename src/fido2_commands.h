// Copyright 2019-2021 Google LLC
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

#ifndef FIDO2_COMMANDS_H_
#define FIDO2_COMMANDS_H_

#include <vector>

#include "absl/types/variant.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace fido2_commands {

// Prints a success message and returns the CBOR response of the authenticator
// in case of success. If any internal checks fail, it terminates the program.
// If the status code is not 0x00, it returns a null optional.
absl::variant<cbor::Value, Status> MakeCredentialPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request);
absl::variant<cbor::Value, Status> GetAssertionPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request);
absl::variant<cbor::Value, Status> GetNextAssertionPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request);
absl::variant<cbor::Value, Status> GetInfoPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker);
absl::variant<cbor::Value, Status> AuthenticatorClientPinPositiveTest(
    DeviceInterface* device, DeviceTracker* device_tracker,
    const cbor::Value& request);
absl::variant<cbor::Value, Status> ResetPositiveTest(DeviceInterface* device);
absl::variant<cbor::Value, Status>
AuthenticatorCredentialManagementPositiveTest(DeviceInterface* device);

// Sends the request to the device and returns the error code passed by the
// authenticator. Warns if you expected a user presence check, but none was
// performed or vice versa.
Status MakeCredentialNegativeTest(DeviceInterface* device,
                                  const cbor::Value& request,
                                  bool expect_up_check);
Status GetAssertionNegativeTest(DeviceInterface* device,
                                const cbor::Value& request,
                                bool expect_up_check);
Status GetNextAssertionNegativeTest(DeviceInterface* device,
                                    const cbor::Value& request,
                                    bool expect_up_check);
Status GetInfoNegativeTest(DeviceInterface* device, const cbor::Value& request);
Status AuthenticatorClientPinNegativeTest(DeviceInterface* device,
                                          const cbor::Value& request,
                                          bool expect_up_check);
Status CredentialManagementNegativeTest(DeviceInterface* device,
                                        const cbor::Value& request,
                                        bool expect_up_check);
Status SelectionNegativeTest(DeviceInterface* device,
                             const cbor::Value& request, bool expect_up_check);
Status LargeBlobsNegativeTest(DeviceInterface* device,
                              const cbor::Value& request, bool expect_up_check);
Status AuthenticatorConfigNegativeTest(DeviceInterface* device,
                                       const cbor::Value& request,
                                       bool expect_up_check);
// Be careful: vendor-specific things might happen here.
// Yubico i.e. only allows for resets in the first 5 seconds after powerup.
Status ResetNegativeTest(DeviceInterface* device, const cbor::Value& request,
                         bool expect_up_check);

// This test is used when checking parameters shared between commands for better
// code reuse.
Status GenericNegativeTest(DeviceInterface* device, const cbor::Value& request,
                           Command command, bool expect_up_check);

// Sends an arbitrary byte vector to the device and expects it to fail. This
// test is useful to try invalid CBOR.
Status NonCborNegativeTest(DeviceInterface* device,
                           const std::vector<uint8_t>& request_bytes,
                           Command command, bool expect_up_check);

}  // namespace fido2_commands
}  // namespace fido2_tests

#endif  // FIDO2_COMMANDS_H_

