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

#ifndef TESTS_FUZZING_CORPUS_H_
#define TESTS_FUZZING_CORPUS_H_

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/monitors/monitor.h"
#include "src/tests/base.h"

namespace fido2_tests {
// TODO(#27) expand test set
// Tests the corpus of make credential command parameters.
class MakeCredentialCorpusTest : public BaseTest {
 public:
  MakeCredentialCorpusTest(fido2_tests::Monitor* monitor,
                           const std::string_view& base_corpus_path);
  std::optional<std::string> Execute(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state) const override;
  void Setup(CommandState* command_state) const override;

 private:
  fido2_tests::Monitor* monitor_;
  std::string_view base_corpus_path_;
};

// Tests the corpus of get assertion command parameters.
class GetAssertionCorpusTest : public BaseTest {
 public:
  GetAssertionCorpusTest(fido2_tests::Monitor* monitor,
                         const std::string_view& base_corpus_path);
  std::optional<std::string> Execute(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state) const override;
  void Setup(CommandState* command_state) const override;

 private:
  fido2_tests::Monitor* monitor_;
  std::string_view base_corpus_path_;
};

// Tests the corpus of client pin command parameters.
class ClientPinCorpusTest : public BaseTest {
 public:
  ClientPinCorpusTest(fido2_tests::Monitor* monitor,
                      const std::string_view& base_corpus_path);
  std::optional<std::string> Execute(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state) const override;
  void Setup(CommandState* command_state) const override;

 private:
  fido2_tests::Monitor* monitor_;
  std::string_view base_corpus_path_;
};

}  // namespace fido2_tests

#endif  // TESTS_FUZZING_CORPUS_H_

