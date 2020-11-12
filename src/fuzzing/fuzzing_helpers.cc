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
    case InputType::kCtapHidRaw:
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
    case InputType::kCtapHidRaw:
      return device->SendCtapHid(input, &response);
    default:
      return Status::kErrOther;
  }
}

}  // namespace fuzzing_helpers
}  // namespace fido2_tests

