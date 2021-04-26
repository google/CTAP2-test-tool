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

#include "src/fuzzing/fuzzing_helpers.h"

#include "glog/logging.h"

namespace fido2_tests {
namespace fuzzing_helpers {

std::string InputTypeToDirectoryName(InputType input_type) {
  // TODO(#27): Extend when more input types are supported.
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return "Cbor_MakeCredentialParameters";
    case InputType::kCborGetAssertionParameter:
      return "Cbor_GetAssertionParameters";
    case InputType::kCborClientPinParameter:
      return "Cbor_ClientPinParameters";
    case InputType::kCborRaw:
      return "Cbor_Raw";
    case InputType::kRawData:
      return "CtapHidRawData";
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }
}

Status SendInput(DeviceInterface* device, InputType input_type,
                 std::vector<uint8_t> const& input) {
  std::vector<uint8_t> response;
  // TODO(#27): Extend when more input types are supported.
  switch (input_type) {
    case InputType::kCborMakeCredentialParameter:
      return device->ExchangeCbor(Command::kAuthenticatorMakeCredential, input,
                                  false, &response);
    case InputType::kCborGetAssertionParameter:
      return device->ExchangeCbor(Command::kAuthenticatorGetAssertion, input,
                                  false, &response);
    case InputType::kCborClientPinParameter:
      return device->ExchangeCbor(Command::kAuthenticatorClientPIN, input,
                                  false, &response);
    default:
      return Status::kErrOther;
  }
}

}  // namespace fuzzing_helpers
}  // namespace fido2_tests

