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

#include "third_party/chromium_components_cbor/values.h"

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

// The command MakeCredential has a parameter map with the following keys.
enum class MakeCredentialParameters : uint8_t {
  kClientDataHash = 0x01,
  kRp = 0x02,
  kUser = 0x03,
  kPubKeyCredParams = 0x04,
  kExcludeList = 0x05,
  kExtensions = 0x06,
  kOptions = 0x07,
  kPinUvAuthParam = 0x08,
  kPinUvAuthProtocol = 0x09,
  kEnterpriseAttestation = 0x0A,
};

// The command GetAssertion has a parameter map with the following keys.
enum class GetAssertionParameters : uint8_t {
  kRpId = 0x01,
  kClientDataHash = 0x02,
  kAllowList = 0x03,
  kExtensions = 0x04,
  kOptions = 0x05,
  kPinUvAuthParam = 0x06,
  kPinUvAuthProtocol = 0x07,
};

// The command ClientPin has a parameter map with the following keys.
enum class ClientPinParameters : uint8_t {
  kPinUvAuthProtocol = 0x01,
  kSubCommand = 0x02,
  kKeyAgreement = 0x03,
  kPinUvAuthParam = 0x04,
  kNewPinEnc = 0x05,
  kPinHashEnc = 0x06,
  kMinPinLength = 0x07,
  kMinPinLengthRpIds = 0x08,
  kPermissions = 0x09,
  kPermissionsRpId = 0x0A,
};

// Contains the map keys for MakeCredential responses.
enum class MakeCredentialResponse : uint8_t {
  kFmt = 0x01,
  kAuthData = 0x02,
  kAttStmt = 0x03,
};

// Converts a MakeCredential response key to a cbor::Value.
cbor::Value CborValue(MakeCredentialResponse response);

// Contains the map keys for GetAssertion responses.
enum class GetAssertionResponse : uint8_t {
  kCredential = 0x01,
  kAuthData = 0x02,
  kSignature = 0x03,
  kUser = 0x04,
  kNumberOfCredentials = 0x05,
};

// Converts a GetAssertion response key to a cbor::Value.
cbor::Value CborValue(GetAssertionResponse response);

// Contains the map keys for GetInfo responses.
enum class InfoMember : uint8_t {
  kVersions = 0x01,
  kExtensions = 0x02,
  kAaguid = 0x03,
  kOptions = 0x04,
  kMaxMsgSize = 0x05,
  kPinUvAuthProtocols = 0x06,
  kMaxCredentialCountInList = 0x07,
  kMaxCredentialIdLength = 0x08,
  kTransports = 0x09,
  kAlgorithms = 0x0A,
  kMaxSerializedLargeBlobArray = 0x0B,
  // 0x0C is intentionally missing.
  kMinPinLength = 0x0D,
  kFirmwareVersion = 0x0E,
  kMaxCredBlobLength = 0x0F,
  kMaxRpIdsForSetMinPinLength = 0x10,
  kPreferredPlatformUvAttempts = 0x11,
  kUvModality = 0x12,
};

// Converts a GetInfo response key to a cbor::Value.
cbor::Value CborValue(InfoMember response);

// Contains the map keys for ClientPin responses.
enum class ClientPinResponse : uint8_t {
  kKeyAgreement = 0x01,
  kPinUvAuthToken = 0x02,
  kPinRetries = 0x03,
  kPowerCycleState = 0x04,
  kUvRetries = 0x05,
};

// Converts a ClientPin response key to a cbor::Value.
cbor::Value CborValue(ClientPinResponse response);

}  // namespace fido2_tests

#endif  // CONSTANTS_H_

