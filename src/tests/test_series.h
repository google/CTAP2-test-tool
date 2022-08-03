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

#ifndef TESTS_TEST_SERIES_H_
#define TESTS_TEST_SERIES_H_

#include <cstdio>

#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"
#include "src/monitors/monitor.h"
#include "src/tests/base.h"

namespace fido2_tests {
namespace runners {

// Returns a list of all tests. Please register all implemented tests here.
const std::vector<std::unique_ptr<BaseTest>>& GetTests();

// Returns a list of all corpus tests.
const std::vector<std::unique_ptr<BaseTest>>& GetCorpusTests(
    fido2_tests::Monitor* monitor, const std::string_view& base_corpus_path);

// Runs all tests. This includes setup, and checking if they are suitable for a
// given authenticator by comparing device information and tags.
void RunTests(DeviceInterface* device, DeviceTracker* device_tracker,
              CommandState* command_state,
              const std::vector<std::unique_ptr<BaseTest>>& tests,
              const std::set<std::string>& test_ids);

}  // namespace runners
}  // namespace fido2_tests

#endif  // TESTS_TEST_SERIES_H_

