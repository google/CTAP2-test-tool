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

#include <cstdint>
#include <iostream>

#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "glog/logging.h"
#include "src/cbor_builders.h"
#include "src/constants.h"
#include "src/crypto_utility.h"
#include "src/fido2_commands.h"
#include "src/tests/test_series.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {

void TestSeries::ClientPinGetPinRetriesTest() {
  AuthenticatorClientPinCborBuilder pin1_builder;
  pin1_builder.AddDefaultsForGetPinRetries();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin1_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin1_builder);
}

void TestSeries::ClientPinGetKeyAgreementTest() {
  // crypto_utility enforces that the COSE key map only has the correct entries.
  AuthenticatorClientPinCborBuilder pin2_builder;
  pin2_builder.AddDefaultsForGetKeyAgreement();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin2_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin2_builder);
}

void TestSeries::ClientPinSetPinTest() {
  AuthenticatorClientPinCborBuilder pin3_builder;
  pin3_builder.AddDefaultsForSetPin(cose_key_example_,
                                    cbor::Value::BinaryValue(),
                                    cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin3_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin3_builder);
}

void TestSeries::ClientPinChangePinTest() {
  AuthenticatorClientPinCborBuilder pin4_builder;
  pin4_builder.AddDefaultsForChangePin(
      cose_key_example_, cbor::Value::BinaryValue(), cbor::Value::BinaryValue(),
      cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin4_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin4_builder);
}

void TestSeries::ClientPinGetPinUvAuthTokenUsingPinTest() {
  AuthenticatorClientPinCborBuilder pin5_builder;
  pin5_builder.AddDefaultsForGetPinUvAuthTokenUsingPin(
      cose_key_example_, cbor::Value::BinaryValue());
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin5_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin5_builder);
}

void TestSeries::ClientPinGetPinUvAuthTokenUsingUvTest() {
  if (!IsFido2Point1Complicant()) {
    return;
  }
  AuthenticatorClientPinCborBuilder pin6_builder;
  pin6_builder.AddDefaultsForGetPinUvAuthTokenUsingUv(cose_key_example_);
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin6_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin6_builder);
}

void TestSeries::ClientPinGetUVRetriesTest() {
  if (!IsFido2Point1Complicant()) {
    return;
  }
  AuthenticatorClientPinCborBuilder pin7_builder;
  pin7_builder.AddDefaultsForGetUvRetries();
  TestBadParameterTypes(Command::kAuthenticatorClientPIN, &pin7_builder);
  TestMissingParameters(Command::kAuthenticatorClientPIN, &pin7_builder);
}

void TestSeries::ClientPinRequirementsTest() {
  Status returned_status;

  cbor::Value::BinaryValue too_short_pin_utf8 = {0x31, 0x32, 0x33};
  cbor::Value::BinaryValue too_short_padded_pin =
      cbor::Value::BinaryValue(64, 0x00);
  for (size_t i = 0; i < too_short_pin_utf8.size(); ++i) {
    too_short_padded_pin[i] = too_short_pin_utf8[i];
  }
  returned_status = command_state_->AttemptSetPin(too_short_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN of length < 4");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  cbor::Value::BinaryValue too_long_padded_pin =
      cbor::Value::BinaryValue(64, 0x30);
  returned_status = command_state_->AttemptSetPin(too_long_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN of length > 63");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  // The minimum length is 4, but the authenticator can enforce more, so only
  // testing the maximum length here.
  // TODO(kaczmarczyck) use minimum PIN length from GetInfo
  cbor::Value::BinaryValue maximum_pin_utf8 =
      cbor::Value::BinaryValue(63, 0x30);
  device_tracker_->CheckAndReport(Status::kErrNone,
                                  command_state_->SetPin(maximum_pin_utf8),
                                  "set PIN of length 63");
  CheckPinByGetAuthToken();

  returned_status = command_state_->AttemptChangePin(too_short_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to change to a PIN of length < 4");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  returned_status = command_state_->AttemptChangePin(too_long_padded_pin);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to change to a PIN of length > 63");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  // Again only testing maximum, not minimum PIN length.
  device_tracker_->CheckAndReport(Status::kErrNone,
                                  command_state_->ChangePin(maximum_pin_utf8),
                                  "change to PIN of length 63");
  CheckPinByGetAuthToken();
}

void TestSeries::ClientPinRequirements2Point1Test() {
  if (!IsFido2Point1Complicant()) {
    return;
  }
  command_state_->Reset();
  Status returned_status;

  cbor::Value::BinaryValue valid_pin_utf8 = {0x31, 0x32, 0x33, 0x34};
  cbor::Value::BinaryValue too_short_padding = cbor::Value::BinaryValue(32);
  for (size_t i = 0; i < valid_pin_utf8.size(); ++i) {
    too_short_padding[i] = valid_pin_utf8[i];
  }
  returned_status = command_state_->AttemptSetPin(too_short_padding);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN padding of length 32");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  cbor::Value::BinaryValue too_long_padding = cbor::Value::BinaryValue(128);
  for (size_t i = 0; i < valid_pin_utf8.size(); ++i) {
    too_long_padding[i] = valid_pin_utf8[i];
  }
  returned_status = command_state_->AttemptSetPin(too_long_padding);
  device_tracker_->CheckAndReport(Status::kErrPinPolicyViolation,
                                  returned_status,
                                  "reject to set a PIN padding of length 128");
  CheckPinAbsenceByMakeCredential();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  returned_status = command_state_->AttemptChangePin(too_short_padding);
  device_tracker_->CheckAndReport(
      Status::kErrPinPolicyViolation, returned_status,
      "reject to change to a PIN padding of length 32");
  CheckPinByGetAuthToken();
  if (returned_status == Status::kErrNone) {
    command_state_->Reset();
  }

  returned_status = command_state_->AttemptChangePin(too_long_padding);
  device_tracker_->CheckAndReport(
      Status::kErrPinPolicyViolation, returned_status,
      "reject to change to a PIN padding of length 128");
  CheckPinByGetAuthToken();
}

void TestSeries::ClientPinRetriesTest() {
  Status returned_status;
  command_state_->Reset();

  int initial_counter = GetPinRetries();
  device_tracker_->CheckAndReport(
      initial_counter <= 8, "maximum PIN retries holds the upper limit of 8");
  device_tracker_->CheckAndReport(initial_counter > 0,
                                  "maximum PIN retries is positive");
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter,
      "PIN retries changed between subsequent calls");

  returned_status = command_state_->AttemptGetAuthToken(bad_pin_);
  device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                  "reject wrong PIN");
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter - 1,
      "PIN retries decrement after a failed attempt");

  test_helpers::AssertCondition(
      command_state_->GetAuthToken() == Status::kErrNone,
      "get auth token for further tests");
  device_tracker_->CheckAndReport(
      GetPinRetries() == initial_counter,
      "PIN retries reset on entering the correct PIN");

  constexpr int kWrongPinsBeforePowerCycle = 3;
  if (initial_counter > kWrongPinsBeforePowerCycle) {
    for (int i = 0; i < kWrongPinsBeforePowerCycle - 1; ++i) {
      returned_status = command_state_->AttemptGetAuthToken(bad_pin_);
      device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                      "reject wrong PIN");
    }
    returned_status = command_state_->AttemptGetAuthToken(bad_pin_);
    device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked, returned_status,
                                    "reject PIN before power cycle");
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter - kWrongPinsBeforePowerCycle,
        "PIN retry counter decremented until blocked");
    returned_status = command_state_->AttemptGetAuthToken(bad_pin_);

    device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked, returned_status,
                                    "reject PIN before power cycle");
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter - kWrongPinsBeforePowerCycle,
        "PIN retry counter does not decrement in a blocked operation");
    command_state_->PromptReplugAndInit();
    test_helpers::AssertCondition(
        command_state_->GetAuthToken() == Status::kErrNone,
        "get auth token for further tests");
    device_tracker_->CheckAndReport(
        GetPinRetries() == initial_counter,
        "PIN retries reset on entering the correct PIN");
  } else {
    std::cout << "The tests for power cycle requirement on "
              << kWrongPinsBeforePowerCycle
              << " consecutive wrong PINs are skipped, because there are at "
                 "most that many retries anyway."
              << std::endl;
  }

  // The next test checks whether the authenticator resets his own key agreement
  // key by reusing the old key material and see if it still works.
  returned_status = command_state_->AttemptGetAuthToken(bad_pin_, false);
  device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                  "reject wrong PIN");
  returned_status = command_state_->AttemptGetAuthToken();
  device_tracker_->CheckAndReport(
      Status::kErrPinInvalid, returned_status,
      "reject even the correct PIN if shared secrets do not match");
  command_state_->PromptReplugAndInit();

  int remaining_retries = GetPinRetries();
  for (int i = 0; i < remaining_retries - 1; ++i) {
    returned_status = command_state_->AttemptGetAuthToken(bad_pin_);
    if (i % 3 != 2) {
      device_tracker_->CheckAndReport(Status::kErrPinInvalid, returned_status,
                                      "reject wrong PIN");
    } else {
      device_tracker_->CheckAndReport(Status::kErrPinAuthBlocked,
                                      returned_status, "reject wrong PIN");
      command_state_->PromptReplugAndInit();
    }
  }
  device_tracker_->CheckAndReport(GetPinRetries() == 1,
                                  "PIN retry counter was reduced to 1");
  returned_status = command_state_->AttemptGetAuthToken(bad_pin_);
  device_tracker_->CheckAndReport(Status::kErrPinBlocked, returned_status,
                                  "block PIN retries if the counter gets to 0");
  device_tracker_->CheckAndReport(GetPinRetries() == 0,
                                  "PIN retry counter was reduced to 0");
  returned_status = command_state_->AttemptGetAuthToken();
  device_tracker_->CheckAndReport(
      Status::kErrPinBlocked, returned_status,
      "reject even the correct PIN if the retry counter is 0");

  command_state_->Reset();
  // TODO(kaczmarczyck) check optional powerCycleState
}

}  // namespace fido2_tests
