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

#include <iostream>

#include "absl/container/flat_hash_set.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "src/command_state.h"
#include "src/constants.h"
#include "src/fuzzing/corpus_controller.h"
#include "src/hid/hid_device.h"
#include "src/monitors/blackbox_monitor.h"
#include "src/monitors/cortexm4_gdb_monitor.h"
#include "src/monitors/gdb_monitor.h"
#include "src/tests/base.h"
#include "src/tests/test_series.h"

static bool ValidatePort(const char* flagname, gflags::int32 value) {
  return value > 0 && value < 65535;
}

static bool ValidateMonitor(const char* flagname, const std::string& value) {
  const absl::flat_hash_set<std::string> kSupportedMonitors = {
      "blackbox", "cortexm4_gdb", "gdb"};
  return kSupportedMonitors.contains(value);
}

DEFINE_string(
    token_path, "",
    "The path to the device on your operating system, usually /dev/hidraw*.");

DEFINE_string(
    corpus_path, "corpus_tests/test_corpus/",
    "The path to the corpus containing seed files to test the device.");

DEFINE_string(monitor, "blackbox", "The monitor type used in fuzzing.");

DEFINE_bool(verbose, false, "Printing debug logs, i.e. transmitted packets.");

DEFINE_int32(port, 2331, "Port to listen on for GDB remote connection.");

DEFINE_validator(port, &ValidatePort);
DEFINE_validator(monitor, &ValidateMonitor);

// Tests the device through all inputs contained in the given corpus.
// Usage example:
//   ./corpus_test --token_path=/dev/hidraw4 --port=2331
//   --corpus_path=corpus_tests/test_corpus/ --verbose
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
    std::cout << "Testing device at path: " << FLAGS_token_path << std::endl;
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

  std::unique_ptr<fido2_tests::Monitor> monitor;
  if (FLAGS_monitor == "blackbox") {
    monitor = std::make_unique<fido2_tests::BlackboxMonitor>();
  } else if (FLAGS_monitor == "cortexm4_gdb") {
    monitor = std::make_unique<fido2_tests::Cortexm4GdbMonitor>(FLAGS_port);
  } else if (FLAGS_monitor == "gdb") {
    monitor = std::make_unique<fido2_tests::GdbMonitor>(FLAGS_port);
  } else {
    CHECK(false) << "unreachable else - TEST SUITE BUG";
  }
  CHECK(monitor->Attach()) << "Monitor failed to attach!";

  fido2_tests::CommandState command_state(device.get(), &tracker);

  std::string corpus_dir = FLAGS_corpus_path;
  if (const char* env_dir = std::getenv("BUILD_WORKSPACE_DIRECTORY")) {
    corpus_dir = absl::StrCat(env_dir, "/", FLAGS_corpus_path);
  }

  const std::vector<std::unique_ptr<fido2_tests::BaseTest>>& tests =
      fido2_tests::runners::GetCorpusTests(monitor.get(), corpus_dir);
  fido2_tests::runners::RunTests(device.get(), &tracker, &command_state, tests,
                                 {});

  std::cout << "\nRESULTS" << std::endl;
  tracker.ReportFindings();
  tracker.SaveResultsToFile("fuzzing_results/");
  return 0;
}

