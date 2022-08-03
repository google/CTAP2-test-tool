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

#include <iostream>

#include "absl/strings/str_split.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "src/command_state.h"
#include "src/constants.h"
#include "src/device_tracker.h"
#include "src/hid/hid_device.h"
#include "src/parameter_check.h"
#include "src/tests/base.h"
#include "src/tests/test_series.h"

DEFINE_string(
    token_path, "",
    "The path to the device on your operating system, usually /dev/hidraw*.");

DEFINE_bool(verbose, false, "Printing debug logs, i.e. transmitted packets.");

DEFINE_string(test_ids, "",
              "Comma-separated list of test IDs to run. Empty runs all tests.");

// Calling this function first connects to the device and then executes all test
// series listed.
//
// Usage example:
//   ./fido2_conformance --token_path=/dev/hidraw4 --verbose
int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_token_path.empty()) {
    std::cout << "Please add the --token_path flag for one of these devices:"
              << std::endl;
    fido2_tests::hid::PrintFidoDevices();
    return 0;
  }

  if (FLAGS_token_path == "_") {
    // This magic value is used by the run script for comfort.
    FLAGS_token_path = fido2_tests::hid::FindFirstFidoDevicePath();
    std::cout << "Tested device path: " << FLAGS_token_path << std::endl;
  }

  fido2_tests::DeviceTracker tracker;
  std::unique_ptr<fido2_tests::DeviceInterface> device =
      std::make_unique<fido2_tests::hid::HidDevice>(&tracker, FLAGS_token_path,
                                                    FLAGS_verbose);
  CHECK(fido2_tests::Status::kErrNone == device->Init())
      << "CTAPHID initialization failed";
  device->Wink();
  std::cout << "This tool will irreversibly delete all credentials on your "
               "device. If one of your plugged security keys stores anything "
               "important, unplug it now before continuing."
            << std::endl;

  // Resets and initializes.
  fido2_tests::CommandState command_state(device.get(), &tracker);
  tracker.AssertCondition(tracker.HasOption("rk"),
                          "Resident key support expected.");
  tracker.AssertCondition(tracker.HasOption("up"),
                          "User presence support expected.");
  tracker.AssertCondition(tracker.HasCborCapability(),
                          "CBOR support expected.");

  std::set<std::string> test_ids;
  if (!FLAGS_test_ids.empty()) {
    test_ids = absl::StrSplit(FLAGS_test_ids, ',');
  }
  // Setup and run all tests, while tracking their results.
  const std::vector<std::unique_ptr<fido2_tests::BaseTest>>& tests =
      fido2_tests::runners::GetTests();
  fido2_tests::runners::RunTests(device.get(), &tracker, &command_state, tests,
                                 test_ids);
  // Reset the device to a clean state.
  command_state.Reset();

  std::cout << "\nRESULTS" << std::endl;
  tracker.ReportFindings();
  tracker.SaveResultsToFile();
}

