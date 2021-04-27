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

#ifndef COMMAND_STATE_H_
#define COMMAND_STATE_H_

#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {

// Tracks the internal state of a security key.
//
// This tool faces a tradeoff between usability and reproducibility of tests. To
// avoid a Reset command after each test, tracking the state of the security key
// helps reducing the number of replugs and touches for user presence.
class CommandState {
 public:
  // Creates the state to a freshly reset security key. Assumes an initialized
  // device, and calls Reset and GetInfo to synchronize and initialize the
  // device_tracker.
  CommandState(DeviceInterface* device, DeviceTracker* device_tracker);
  // Prompts the user to replug the device which is required before operations
  // that need a power cycle (i.e. resetting). The Init will then handle device
  // initilalization, regardless of the current state of the device.
  void PromptReplugAndInit();
  // Calls the Reset command to reset the state of the device.
  void Reset();
  // Takes actions until the state is neutral. Call this function before
  // executing a test. If your test needs user verification to work, use set_uv.
  void Prepare(bool set_uv = false);
  // Makes a credential for all tests that require one, for example assertions.
  // Works with or without a PIN being set.
  absl::variant<cbor::Value, Status> MakeTestCredential(std::string rp_id,
                                                        bool use_resident_key);
  // Calls the GetKeyAgreement subcommand and returns its result.
  absl::variant<cbor::Value, Status> GetKeyAgreementValue();
  // Computes the shared secret between authenticator and platform. Sets the
  // argument platform_cose_key to the EC key used during the transaction.
  Status ComputeSharedSecret();
  // Sets the PIN to the value specified in new_pin_utf8. Performs key agreement
  // if not already done. Safe to call multiple times, and only talks to the
  // authenticator if there is no PIN already. Defaults to 1234 if nothing else
  // is set. Fails if the PIN requirements are not satisfied.
  Status SetPin(const cbor::Value::BinaryValue& new_pin_utf8);
  // Sets the PIN as above, using a default.
  Status SetPin();
  // Calls the SetPin command with the given padded PIN. Fails if the length is
  // not a multiple of the AES block size. Returns the command's status code.
  // Performs key agreement if not already done.
  Status AttemptSetPin(const cbor::Value::BinaryValue& new_padded_pin);
  // Changes the current PIN to new_pin_utf8. Fails if the PIN requirements are
  // not satisfied. Creates a PIN if not already done.
  Status ChangePin(const cbor::Value::BinaryValue& new_pin_utf8);
  // Calls the ChangePin command with the given padded PIN, using the currently
  // set PIN. Fails if the length is not a multiple of the AES block size.
  // Returns the command's status code. Creates a PIN if not already done.
  Status AttemptChangePin(const cbor::Value::BinaryValue& new_padded_pin);
  // Returns a PIN Auth token valid for this power cycle from the authenticator.
  // Defaults the PIN if none exists and set_pin_if_necessary is true.
  Status GetAuthToken(bool set_pin_if_necessary = true);
  // Calls the GetAuthToken command with the given PIN. Creates a PIN if
  // not already done. The tested PIN defaults to 1234, which should work with
  // SetPin's default. Returns the command's status code. If redo_key_agreement
  // is true, it brings the shared_secret back to a valid state. This is
  // necessary because authenticators reset the key agreement on failed PIN
  // hash checks. Setting redo_key_agreement is only used for specific failure
  // mode tests.
  Status AttemptGetAuthToken(const cbor::Value::BinaryValue& pin_utf8,
                             bool redo_key_agreement = true);
  // Attemps to call GetAuthToken as above, using a default PIN and redoing the
  // key agreements afterwards.
  Status AttemptGetAuthToken();
  // Returns the currently stored auth token. This value represents what should
  // be the internal state of the device right now (or is empty if unknown).
  cbor::Value::BinaryValue GetCurrentAuthToken();

 private:
  DeviceInterface* device_;
  DeviceTracker* device_tracker_;
  // The PIN is persistent, the other state is kept for a power cycle.
  cbor::Value::MapValue platform_cose_key_;
  cbor::Value::BinaryValue shared_secret_;
  cbor::Value::BinaryValue pin_utf8_;
  cbor::Value::BinaryValue auth_token_;
};

}  // namespace fido2_tests

#endif  // COMMAND_STATE_H_

