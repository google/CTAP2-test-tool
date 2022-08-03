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

#include "src/tests/test_series.h"

#include "src/tests/client_pin.h"
#include "src/tests/fuzzing_corpus.h"
#include "src/tests/general.h"
#include "src/tests/get_assertion.h"
#include "src/tests/make_credential.h"
#include "src/tests/reset.h"

namespace fido2_tests {
namespace runners {

const std::vector<std::unique_ptr<BaseTest>>& GetTests() {
  static const auto* const tests = [] {
    auto* test_list = new std::vector<std::unique_ptr<BaseTest>>;
    test_list->push_back(
        std::make_unique<MakeCredentialBadParameterTypesTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialMissingParameterTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialRelyingPartyEntityTest>());
    test_list->push_back(std::make_unique<MakeCredentialUserEntityTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialExcludeListCredentialDescriptorTest>());
    test_list->push_back(std::make_unique<MakeCredentialExtensionsTest>());
    test_list->push_back(std::make_unique<MakeCredentialExcludeListTest>());
    test_list->push_back(std::make_unique<MakeCredentialCredParamsTest>());
    test_list->push_back(std::make_unique<MakeCredentialOptionRkTest>());
    test_list->push_back(std::make_unique<MakeCredentialOptionUpFalseTest>());
    test_list->push_back(std::make_unique<MakeCredentialOptionUvFalseTest>());
    test_list->push_back(std::make_unique<MakeCredentialOptionUvTrueTest>());
    test_list->push_back(std::make_unique<MakeCredentialOptionUnknownTest>());
    test_list->push_back(std::make_unique<MakeCredentialPinAuthEmptyTest>());
    test_list->push_back(std::make_unique<MakeCredentialPinAuthProtocolTest>());
    test_list->push_back(std::make_unique<MakeCredentialPinAuthNoPinTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialPinAuthEmptyWithPinTest>());
    test_list->push_back(std::make_unique<MakeCredentialPinAuthTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialPinAuthMissingParameterTest>());
    test_list->push_back(std::make_unique<MakeCredentialDuplicateTest>());
    test_list->push_back(std::make_unique<MakeCredentialFullStoreTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialPhysicalPresenceTest>());
    test_list->push_back(
        std::make_unique<MakeCredentialNonAsciiDisplayNameTest>());
    test_list->push_back(std::make_unique<MakeCredentialUtf8DisplayNameTest>());
    test_list->push_back(std::make_unique<MakeCredentialHmacSecretTest>());

    test_list->push_back(std::make_unique<GetAssertionBadParameterTypesTest>());
    test_list->push_back(std::make_unique<GetAssertionMissingParameterTest>());
    test_list->push_back(
        std::make_unique<GetAssertionAllowListCredentialDescriptorTest>());
    test_list->push_back(std::make_unique<GetAssertionExtensionsTest>());
    test_list->push_back(std::make_unique<GetAssertionOptionRkTest>());
    test_list->push_back(std::make_unique<GetAssertionOptionUpTest>());
    test_list->push_back(std::make_unique<GetAssertionOptionUvFalseTest>());
    test_list->push_back(std::make_unique<GetAssertionOptionUvTrueTest>());
    test_list->push_back(std::make_unique<GetAssertionOptionUnknownTest>());
    test_list->push_back(std::make_unique<GetAssertionResidentKeyTest>());
    test_list->push_back(std::make_unique<GetAssertionNonResidentKeyTest>());
    test_list->push_back(std::make_unique<GetAssertionPinAuthEmptyTest>());
    test_list->push_back(std::make_unique<GetAssertionPinAuthProtocolTest>());
    test_list->push_back(std::make_unique<GetAssertionPinAuthNoPinTest>());
    test_list->push_back(
        std::make_unique<GetAssertionPinAuthEmptyWithPinTest>());
    test_list->push_back(std::make_unique<GetAssertionPinAuthTest>());
    test_list->push_back(
        std::make_unique<GetAssertionPinAuthMissingParameterTest>());
    test_list->push_back(std::make_unique<GetAssertionPhysicalPresenceTest>());
    test_list->push_back(std::make_unique<GetAssertionEmptyUserIdTest>());

    test_list->push_back(
        std::make_unique<GetPinRetriesBadParameterTypesTest>());
    test_list->push_back(std::make_unique<GetPinRetriesMissingParameterTest>());
    test_list->push_back(
        std::make_unique<GetKeyAgreementBadParameterTypesTest>());
    test_list->push_back(
        std::make_unique<GetKeyAgreementMissingParameterTest>());
    test_list->push_back(std::make_unique<SetPinBadParameterTypesTest>());
    test_list->push_back(std::make_unique<SetPinMissingParameterTest>());
    test_list->push_back(std::make_unique<ChangePinBadParameterTypesTest>());
    test_list->push_back(std::make_unique<ChangePinMissingParameterTest>());
    test_list->push_back(std::make_unique<GetPinTokenBadParameterTypesTest>());
    test_list->push_back(std::make_unique<GetPinTokenMissingParameterTest>());
    test_list->push_back(
        std::make_unique<
            GetPinUvAuthTokenUsingUvWithPermissionsBadParameterTypesTest>());
    test_list->push_back(
        std::make_unique<
            GetPinUvAuthTokenUsingUvWithPermissionsMissingParameterTest>());
    test_list->push_back(std::make_unique<GetUVRetriesBadParameterTypesTest>());
    test_list->push_back(std::make_unique<GetUVRetriesMissingParameterTest>());
    test_list->push_back(std::make_unique<ClientPinRequirementsSetPinTest>());
    test_list->push_back(
        std::make_unique<ClientPinRequirementsChangePinTest>());
    test_list->push_back(
        std::make_unique<ClientPinNewRequirementsSetPinTest>());
    test_list->push_back(
        std::make_unique<ClientPinNewRequirementsChangePinTest>());
    test_list->push_back(std::make_unique<ClientPinOldKeyMaterialTest>());
    test_list->push_back(std::make_unique<ClientPinGeneralPinRetriesTest>());
    test_list->push_back(std::make_unique<ClientPinAuthBlockPinRetriesTest>());
    test_list->push_back(std::make_unique<ClientPinBlockPinRetriesTest>());

    test_list->push_back(std::make_unique<GetInfoTest>());
    test_list->push_back(std::make_unique<PersistentCredentialsTest>());
    test_list->push_back(std::make_unique<PersistentPinRetriesTest>());
    test_list->push_back(std::make_unique<RegeneratesPinAuthTest>());
    test_list->push_back(std::make_unique<WinkTest>());

    test_list->push_back(std::make_unique<DeleteCredentialsTest>());
    test_list->push_back(std::make_unique<DeletePinTest>());
    test_list->push_back(std::make_unique<ResetPhysicalPresenceTest>());
    return test_list;
  }();
  return *tests;
}

const std::vector<std::unique_ptr<BaseTest>>& GetCorpusTests(
    fido2_tests::Monitor* monitor, const std::string_view& base_corpus_path) {
  static const auto* const tests = [monitor, base_corpus_path] {
    auto* test_list = new std::vector<std::unique_ptr<BaseTest>>;
    // TODO(#27) extend tests
    test_list->push_back(
        std::make_unique<MakeCredentialCorpusTest>(monitor, base_corpus_path));
    test_list->push_back(
        std::make_unique<GetAssertionCorpusTest>(monitor, base_corpus_path));
    test_list->push_back(
        std::make_unique<ClientPinCorpusTest>(monitor, base_corpus_path));
    return test_list;
  }();
  return *tests;
}

void RunTests(DeviceInterface* device, DeviceTracker* device_tracker,
              CommandState* command_state,
              const std::vector<std::unique_ptr<BaseTest>>& tests,
              const std::set<std::string>& test_ids) {
  for (const auto& test : tests) {
    if (!test_ids.empty() && test_ids.find(test->GetId()) == test_ids.end()) {
      continue;
    }
    if (test->HasTag(Tag::kClientPin) &&
        !device_tracker->HasOption("clientPin")) {
      continue;
    }
    if (test->HasTag(Tag::kHmacSecret) &&
        !device_tracker->HasExtension("hmac-secret")) {
      continue;
    }
    // TODO(#16) replace version string with FIDO_2_1 when specification is
    // final
    if (test->HasTag(Tag::kFido2Point1) &&
        !device_tracker->HasVersion("FIDO_2_1_PRE")) {
      continue;
    }
    test->Setup(command_state);
    std::optional<std::string> error_message =
        test->Execute(device, device_tracker, command_state);
    // If tests involving the PIN fail, the internal state might not track the
    // actual device state correctly.
    if (error_message.has_value() && test->HasTag(Tag::kClientPin)) {
      command_state->Reset();
    }
    device_tracker->LogTest(test->GetId(), test->GetDescription(),
                            error_message, test->ListTags());
  }
}

}  // namespace runners
}  // namespace fido2_tests

