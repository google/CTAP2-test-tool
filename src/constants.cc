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

#include "src/constants.h"

#include "glog/logging.h"

namespace fido2_tests {

std::string StatusToString(Status status) {
  switch (status) {
    case Status::kErrNone:
      return "CTAP2_OK";
    case Status::kErrInvalidCommand:
      return "CTAP1_ERR_INVALID_COMMAND";
    case Status::kErrInvalidParameter:
      return "CTAP1_ERR_INVALID_PARAMETER";
    case Status::kErrInvalidLength:
      return "CTAP1_ERR_INVALID_LENGTH";
    case Status::kErrInvalidSeq:
      return "CTAP1_ERR_INVALID_SEQ";
    case Status::kErrTimeout:
      return "CTAP1_ERR_TIMEOUT";
    case Status::kErrChannelBusy:
      return "CTAP1_ERR_CHANNEL_BUSY";
    case Status::kErrLockRequired:
      return "CTAP1_ERR_LOCK_REQUIRED";
    case Status::kErrInvalidChannel:
      return "CTAP1_ERR_INVALID_CHANNEL";
    case Status::kErrCborUnexpectedType:
      return "CTAP2_ERR_CBOR_UNEXPECTED_TYPE";
    case Status::kErrInvalidCbor:
      return "CTAP2_ERR_INVALID_CBOR";
    case Status::kErrMissingParameter:
      return "CTAP2_ERR_MISSING_PARAMETER";
    case Status::kErrLimitExceeded:
      return "CTAP2_ERR_LIMIT_EXCEEDED";
    case Status::kErrUnsupportedExtension:
      return "CTAP2_ERR_UNSUPPORTED_EXTENSION";
    case Status::kErrCredentialExcluded:
      return "CTAP2_ERR_CREDENTIAL_EXCLUDED";
    case Status::kErrProcessing:
      return "CTAP2_ERR_PROCESSING";
    case Status::kErrInvalidCredential:
      return "CTAP2_ERR_INVALID_CREDENTIAL";
    case Status::kErrUserActionPending:
      return "CTAP2_ERR_USER_ACTION_PENDING";
    case Status::kErrOperationPending:
      return "CTAP2_ERR_OPERATION_PENDING";
    case Status::kErrNoOperations:
      return "CTAP2_ERR_NO_OPERATIONS";
    case Status::kErrUnsupportedAlgorithm:
      return "CTAP2_ERR_UNSUPPORTED_ALGORITHM";
    case Status::kErrOperationDenied:
      return "CTAP2_ERR_OPERATION_DENIED";
    case Status::kErrKeyStoreFull:
      return "CTAP2_ERR_KEY_STORE_FULL";
    case Status::kErrNoOperationPending:
      return "CTAP2_ERR_NO_OPERATION_PENDING";
    case Status::kErrUnsupportedOption:
      return "CTAP2_ERR_UNSUPPORTED_OPTION";
    case Status::kErrInvalidOption:
      return "CTAP2_ERR_INVALID_OPTION";
    case Status::kErrKeepaliveCancel:
      return "CTAP2_ERR_KEEPALIVE_CANCEL";
    case Status::kErrNoCredentials:
      return "CTAP2_ERR_NO_CREDENTIALS";
    case Status::kErrUserActionTimeout:
      return "CTAP2_ERR_USER_ACTION_TIMEOUT";
    case Status::kErrNotAllowed:
      return "CTAP2_ERR_NOT_ALLOWED";
    case Status::kErrPinInvalid:
      return "CTAP2_ERR_PIN_INVALID";
    case Status::kErrPinBlocked:
      return "CTAP2_ERR_PIN_BLOCKED";
    case Status::kErrPinAuthInvalid:
      return "CTAP2_ERR_PIN_AUTH_INVALID";
    case Status::kErrPinAuthBlocked:
      return "CTAP2_ERR_PIN_AUTH_BLOCKED";
    case Status::kErrPinNotSet:
      return "CTAP2_ERR_PIN_NOT_SET";
    case Status::kErrPinRequired:
      return "CTAP2_ERR_PIN_REQUIRED";
    case Status::kErrPinPolicyViolation:
      return "CTAP2_ERR_PIN_POLICY_VIOLATION";
    case Status::kErrPinTokenExpired:
      return "CTAP2_ERR_PIN_TOKEN_EXPIRED";
    case Status::kErrRequestTooLarge:
      return "CTAP2_ERR_REQUEST_TOO_LARGE";
    case Status::kErrActionTimeout:
      return "CTAP2_ERR_ACTION_TIMEOUT";
    case Status::kErrUpRequired:
      return "CTAP2_ERR_UP_REQUIRED";
    case Status::kErrUvBlocked:
      return "CTAP2_ERR_UV_BLOCKED";
    case Status::kErrTestToolInternal:
      return "TEST TOOL FOUND A PROBLEM";
    case Status::kErrOther:
      return "CTAP1_ERR_OTHER";
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }
}

std::string CommandToString(Command command) {
  switch (command) {
    case Command::kAuthenticatorMakeCredential:
      return "make credential command";
    case Command::kAuthenticatorGetAssertion:
      return "get assertion command";
    case Command::kAuthenticatorGetInfo:
      return "get info command";
    case Command::kAuthenticatorClientPIN:
      return "client PIN command";
    case Command::kAuthenticatorReset:
      return "reset command";
    case Command::kAuthenticatorGetNextAssertion:
      return "get next assertion command";
    case Command::kAuthenticatorBioEnrollment:
      return "bio enrollment command";
    case Command::kAuthenticatorCredentialManagement:
      return "credential management command";
    case Command::kAuthenticatorSelection:
      return "selection command";
    case Command::kAuthenticatorLargeBlobs:
      return "large blobs command";
    case Command::kAuthenticatorConfig:
      return "config command";
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }
}

cbor::Value CborInt(Algorithm alg) {
  return cbor::Value(static_cast<int>(alg));
}

bool MakeCredentialResponseContains(int64_t key) {
  return key >= 0x01 && key <= 0x05;
}

bool GetAssertionResponseContains(int64_t key) {
  return key >= 0x01 && key <= 0x07;
}

bool InfoMemberContains(int64_t key) { return key >= 0x01 && key <= 0x15; }

bool ClientPinResponseContains(int64_t key) {
  return key >= 0x01 && key <= 0x05;
}

bool CredentialManagementResponseContains(int64_t key) {
  return key >= 0x01 && key <= 0x0B;
}

bool LargeBlobsResponseContains(int64_t key) { return key == 0x01; }

bool BioEnrollmentResponseContains(int64_t key) {
  return key >= 0x01 && key <= 0x08;
}

}  // namespace fido2_tests

