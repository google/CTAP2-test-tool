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
  kErrTestToolInternal = 0x7E,
  kErrOther = 0x7F
};

// Returns a Status, if it is an error.
#define OK_OR_RETURN(x)                 \
  do {                                  \
    Status __status = (x);              \
    if (__status != Status::kErrNone) { \
      return __status;                  \
    }                                   \
  } while (0)

// Converts a Status to a string for printing.
std::string StatusToString(Status status);

// These are the possible CTAP commands.
enum class Command : uint8_t {
  kAuthenticatorMakeCredential = 0x01,
  kAuthenticatorGetAssertion = 0x02,
  kAuthenticatorGetInfo = 0x04,
  kAuthenticatorClientPIN = 0x06,
  kAuthenticatorReset = 0x07,
  kAuthenticatorGetNextAssertion = 0x08,
  kAuthenticatorBioEnrollment = 0x09,
  kAuthenticatorCredentialManagement = 0x0A,
  kAuthenticatorSelection = 0x0B,
  kAuthenticatorLargeBlobs = 0x0C,
  kAuthenticatorConfig = 0x0D,
};

// Converts a Command to a string for printing.
std::string CommandToString(Command command);

// ES256 and RS256 are for signatures, while ECDH is for key agreement.
enum class Algorithm {
  kEs256Algorithm = -7,
  kEcdhEsHkdf256 = -25,
  kRs256Algorithm = -257
};

// Converts a the algorithm to a cbor::Value.
cbor::Value CborInt(Algorithm alg);

// Converts parameter, response and subcommand keys to cbor::Value.
template <typename T>
cbor::Value CborInt(T variant) {
  return cbor::Value(static_cast<uint8_t>(variant));
}

// The ClientPin command has these sub commands.
enum class PinSubCommand : uint8_t {
  kGetPinRetries = 0x01,
  kGetKeyAgreement = 0x02,
  kSetPin = 0x03,
  kChangePin = 0x04,
  kGetPinToken = 0x05,
  kGetPinUvAuthTokenUsingUvWithPermissions = 0x06,
  kGetUvRetries = 0x07,
  // Sub command 0x08 existed in a draft, but was removed.
  kGetPinUvAuthTokenUsingPinWithPermissions = 0x09,
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
  kPermissions = 0x09,
  kPermissionsRpId = 0x0A,
};

// Contains the map keys for MakeCredential responses.
enum class MakeCredentialResponse : uint8_t {
  kFmt = 0x01,
  kAuthData = 0x02,
  kAttStmt = 0x03,
  kEpAtt = 0x04,
  kLargeBlobKey = 0x05,
};

// Checks if the key is used in this enum.
bool MakeCredentialResponseContains(int64_t key);

// Contains the map keys for GetAssertion responses.
enum class GetAssertionResponse : uint8_t {
  kCredential = 0x01,
  kAuthData = 0x02,
  kSignature = 0x03,
  kUser = 0x04,
  kNumberOfCredentials = 0x05,
  kUserSelected = 0x06,
  kLargeBlobKey = 0x07,
};

// Checks if the key is used in this enum.
bool GetAssertionResponseContains(int64_t key);

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
  kForcePinChange = 0x0C,
  kMinPinLength = 0x0D,
  kFirmwareVersion = 0x0E,
  kMaxCredBlobLength = 0x0F,
  kMaxRpIdsForSetMinPinLength = 0x10,
  kPreferredPlatformUvAttempts = 0x11,
  kUvModality = 0x12,
  kCertifications = 0x13,
  kRemainingDiscoverableCredentials = 0x14,
  kVendorPrototypeConfigCommands = 0x15,
};

// Checks if the key is used in this enum.
bool InfoMemberContains(int64_t key);

// Contains the map keys for ClientPin responses.
enum class ClientPinResponse : uint8_t {
  kKeyAgreement = 0x01,
  kPinUvAuthToken = 0x02,
  kPinRetries = 0x03,
  kPowerCycleState = 0x04,
  kUvRetries = 0x05,
};

// Checks if the key is used in this enum.
bool ClientPinResponseContains(int64_t key);

// The command CredentialManagement has a parameter map with the following keys.
enum class CredentialManagementParameters : uint8_t {
  kSubCommand = 0x01,
  kSubCommandParams = 0x02,
  kPinUvAuthProtocol = 0x03,
  kPinUvAuthParam = 0x04,
};

// Contains the map keys for CredentialManagement responses.
enum class CredentialManagementResponse : uint8_t {
  kExistingResidentCredentialsCount = 0x01,
  kMaxPossibleRemainingResidentCredentialsCount = 0x02,
  kRp = 0x03,
  kRpIdHash = 0x04,
  kTotalRps = 0x05,
  kUser = 0x06,
  kCredentialId = 0x07,
  kPublicKey = 0x08,
  kTotalCredentials = 0x09,
  kCredProtect = 0x0A,
  kLargeBlobKey = 0x0B,
};

// Checks if the key is used in this enum.
bool CredentialManagementResponseContains(int64_t key);

// The CredentialManagement command has these sub commands.
enum class ManagementSubCommand : uint8_t {
  kGetCredsMetadata = 0x01,
  kEnumerateRpsBegin = 0x02,
  kEnumerateRpsGetNextRp = 0x03,
  kEnumerateCredentialsBegin = 0x04,
  kEnumerateCredentialsGetNextCredential = 0x05,
  kDeleteCredential = 0x06,
  kUpdateUserInformation = 0x07,
};

// The CredentialManagement sub commands have these parameters.
enum class ManagementSubCommandParams : uint8_t {
  kRpIdHash = 0x01,
  kCredentialId = 0x02,
  kUser = 0x03,
};

// The command BioEnrollment has a parameter map with the following keys.
enum class BioEnrollmentParameters : uint8_t {
  kModality = 0x01,
  kSubCommand = 0x02,
  kSubCommandParams = 0x03,
  kPinUvAuthProtocol = 0x04,
  kPinUvAuthParam = 0x05,
  kGetModality = 0x06,
};

// Contains the map keys for BioEnrollment responses.
enum class BioEnrollmentResponse : uint8_t {
  kModality = 0x01,
  kFingerprintKind = 0x02,
  kMaxCaptureSamplesRequiredForEnroll = 0x03,
  kTemplateId = 0x04,
  kLastEnrollSampleStatus = 0x05,
  kRemainingSamples = 0x06,
  kTemplateInfos = 0x07,
  kMaxTemplateFriendlyName = 0x08,
};

// Checks if the key is used in this enum.
bool BioEnrollmentResponseContains(int64_t key);

// The BioEnrollment command has these sub commands.
enum class BioEnrollmentSubCommand : uint8_t {
  kEnrollBegin = 0x01,
  kEnrollCaptureNextSample = 0x02,
  kCancelCurrentEnrollment = 0x03,
  kEnumerateEnrollments = 0x04,
  kSetFriendlyName = 0x05,
  kRemoveEnrollment = 0x06,
  kGetFingerprintSensorInfo = 0x07,
};

// The BioEnrollment sub commands have these parameters.
enum class BioEnrollmentSubCommandParams : uint8_t {
  kTemplateId = 0x01,
  kTemplateFriendlyName = 0x02,
  kTimeoutMilliseconds = 0x03,
};

// The command LargeBlobs has a parameter map with the following keys.
enum class LargeBlobsParameters : uint8_t {
  kGet = 0x01,
  kSet = 0x02,
  kOffset = 0x03,
  kLength = 0x04,
  kPinUvAuthParam = 0x05,
  kPinUvAuthProtocol = 0x06,
};

// Contains the map keys for LargeBlobs responses.
enum class LargeBlobsResponse : uint8_t {
  kConfig = 0x01,
};

// Checks if the key is used in this enum.
bool LargeBlobsResponseContains(int64_t key);

// The command Config has a parameter map with the following keys.
enum class ConfigParameters : uint8_t {
  kSubCommand = 0x01,
  kSubCommandParams = 0x02,
  kPinUvAuthProtocol = 0x03,
  kPinUvAuthParam = 0x04,
};

// The Config command has these sub commands.
enum class ConfigSubCommand : uint8_t {
  kEnableEnterpriseAttestation = 0x01,
  kToggleAlwaysUv = 0x02,
  kSetMinPinLength = 0x03,
  kVendorPrototype = 0x04,
};

// The Configsub commands have these parameters.
enum class ConfigSubCommandParams : uint8_t {
  kNewMinPinLength = 0x01,
  kMinPinLengthRpIds = 0x02,
  kForceChangePin = 0x03,
};

}  // namespace fido2_tests

#endif  // CONSTANTS_H_

