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

#include "src/tests/test_series.h"

#include "src/tests/fuzzing_corpus.h"
#include "src/tests/general.h"
#include "src/tests/reset.h"

namespace fido2_tests {
namespace runners {

const std::vector<std::unique_ptr<BaseTest>>& GetTests() {
  static const auto* const tests = [] {
    auto* test_list = new std::vector<std::unique_ptr<BaseTest>>;
    test_list->push_back(std::make_unique<GetInfoTest>());
    test_list->push_back(std::make_unique<PersistentCredentialsTest>());
    test_list->push_back(std::make_unique<PersistentPinRetriesTest>());
    test_list->push_back(std::make_unique<RegeneratesPinAuthTest>());
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
              const std::vector<std::unique_ptr<BaseTest>>& tests) {
  for (const auto& test : tests) {
    // TODO(kaczmarczyck) compare tags and info in device_tracker
    test->Setup(command_state);
    std::optional<std::string> error_message =
        test->Execute(device, device_tracker, command_state);
    device_tracker->LogTest(test->GetId(), test->GetDescription(),
                            error_message);
  }
}

}  // namespace runners
}  // namespace fido2_tests

