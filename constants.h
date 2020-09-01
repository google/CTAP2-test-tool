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

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <cstdint>
#include <string>

namespace fido2_tests {
// This is the status byte returned by CTAP interactions.
enum class Status : uint8_t {
  kErrNone = 0x00,
  kErrInvalidCommand = 0x01,
  kErrInvalidParameter = 0x02,
  kErrInvalidLength = 0x03,
  kErrInvalidSeq = 0x04,
  kErrTimeout = 0x05,
  kErrChannelBusy = 0x06,
  kErrLockRequired = 0x0A,
  kErrInvalidChannel = 0x0B,
  kErrCborUnexpectedType = 0x11,
  kErrInvalidCbor = 0x12,
  kErrMissingParameter = 0x14,
  kErrLimitExceeded = 0x15,
  kErrUnsupportedExtension = 0x16,
  kErrCredentialExcluded = 0x19,
  kErrProcessing = 0x21,
  kErrInvalidCredential = 0x22,
  kErrUserActionPending = 0x23,
  kErrOperationPending = 0x24,
  kErrNoOperations = 0x25,
  kErrUnsupportedAlgorithm = 0x26,
  kErrOperationDenied = 0x27,
  kErrKeyStoreFull = 0x28,
  kErrNoOperationPending = 0x2A,
  kErrUnsupportedOption = 0x2B,
  kErrInvalidOption = 0x2C,
  kErrKeepaliveCancel = 0x2D,
  kErrNoCredentials = 0x2E,
  kErrUserActionTimeout = 0x2F,
  kErrNotAllowed = 0x30,
  kErrPinInvalid = 0x31,
  kErrPinBlocked = 0x32,
  kErrPinAuthInvalid = 0x33,
  kErrPinAuthBlocked = 0x34,
  kErrPinNotSet = 0x35,
  kErrPinRequired = 0x36,
  kErrPinPolicyViolation = 0x37,
  kErrPinTokenExpired = 0x38,
  kErrRequestTooLarge = 0x39,
  kErrActionTimeout = 0x3A,
  kErrUpRequired = 0x3B,
  kErrUvBlocked = 0x3C,
  kErrOther = 0x7F
};

// Converts a Status to a string for printing.
std::string StatusToString(Status status);

// These are the possible CTAP commands.
enum class Command : uint8_t {
  kAuthenticatorMakeCredential = 0x01,
  kAuthenticatorGetAssertion = 0x02,
  kAuthenticatorGetInfo = 0x04,
  kAuthenticatorClientPIN = 0x06,
  kAuthenticatorReset = 0x07,
  kAuthenticatorGetNextAssertion = 0x08
};

// Converts a Command to a string for printing.
std::string CommandToString(Command command);

// ES256 and RS256 are for signatures, while ECDH is for key agreement.
enum class Algorithm {
  kEs256Algorithm = -7,
  kEcdhEsHkdf256 = -25,
  kRs256Algorithm = -257
};

// The reset command has a few sub commands with the following representations.
enum class PinSubCommand : uint8_t {
  kGetPinRetries = 0x01,
  kGetKeyAgreement = 0x02,
  kSetPin = 0x03,
  kChangePin = 0x04,
  kGetPinToken = 0x05,
  kGetPinUvAuthTokenUsingPin = 0x05,
  kGetPinUvAuthTokenUsingUv = 0x06,
  kGetUvRetries = 0x07
};

// A keepalive packet has two possible status bytes, or errors.
enum class KeepaliveStatus : uint8_t {
  kStatusProcessing = 0x01,
  kStatusUpNeeded = 0x02,
  kStatusError
};
}  // namespace fido2_tests

#endif  // CONSTANTS_H_
