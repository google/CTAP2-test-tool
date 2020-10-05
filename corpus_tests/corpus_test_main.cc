// Copyright 2020 Google LLC
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

#include "corpus_tests/monitor.h"
#include "corpus_tests/test_input_controller.h"
#include "gflags/gflags.h"
#include "glog/logging.h"
#include "src/constants.h"
#include "src/hid/hid_device.h"

static bool ValidatePort(const char* flagname, gflags::int32 value) {
  if (value > 0 && value < 65535) {
    return true;
  }
  LOG(ERROR) << "Invalid value for --" << flagname << ": "
             << static_cast<int>(value);
  return false;
}

DEFINE_string(
    token_path, "",
    "The path to the device on your operating system, usually /dev/hidraw*.");

DEFINE_string(
    corpus_path, "corpus_tests/test_corpus/",
    "The path to the corpus containing seed files to test the device.");

DEFINE_int32(port, 0, "Port to listen on for GDB remote connection.");

DEFINE_validator(port, &ValidatePort);

// Tests the device through all inputs contained in the given corpus.
// Usage example:
//   ./corpus_test --token_path=/dev/hidraw4 --port=2331
//   --corpus_path=corpus_tests/test_corpus/
int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  if (FLAGS_token_path.empty()) {
    std::cout << "Please add the --token_path flag for one of these devices:"
              << std::endl;
    fido2_tests::hid::PrintFidoDevices();
    return 0;
  }

  fido2_tests::DeviceTracker tracker;
  std::unique_ptr<fido2_tests::DeviceInterface> device =
      absl::make_unique<fido2_tests::hid::HidDevice>(&tracker,
                                                     FLAGS_token_path);
  CHECK(fido2_tests::Status::kErrNone == device->Init())
      << "CTAPHID initialization failed";

  corpus_tests::Monitor monitor;
  CHECK(monitor.Attach(device.get(), FLAGS_port))
      << "Monitor failed to attach!";
  CHECK(monitor.Start()) << "Monitor failed to start!";

  std::string corpus_dir = FLAGS_corpus_path;
  if (const char* env_dir = std::getenv("BUILD_WORKSPACE_DIRECTORY")) {
    corpus_dir = absl::StrCat(env_dir, "/", FLAGS_corpus_path);
  }
  corpus_tests::CorpusIterator corpus_iterator(corpus_dir);
  while (corpus_iterator.HasNextInput()) {
    auto [input_type, input_data, input_path] = corpus_iterator.GetNextInput();
    std::cout << "Running file " << input_path << std::endl;
    corpus_tests::SendInput(device.get(), input_type, input_data);
    if (monitor.DeviceCrashed()) {
      LOG(ERROR) << "DEVICE CRASHED!";
      monitor.SaveCrashFile(input_type, input_path);
      monitor.PrintCrashReport();
      break;
    }
  }
  return 0;
}