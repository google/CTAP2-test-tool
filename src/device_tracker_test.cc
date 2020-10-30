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

#include "src/device_tracker.h"

#include "gtest/gtest.h"
#include "src/constants.h"
#include "third_party/chromium_components_cbor/values.h"

namespace fido2_tests {
namespace {

TEST(DeviceTracker, TestInitialize) {
  DeviceTracker device_tracker = DeviceTracker();
  cbor::Value::ArrayValue versions;
  versions.push_back(cbor::Value("VERSION"));
  cbor::Value::ArrayValue extensions;
  extensions.push_back(cbor::Value("EXTENSION"));
  cbor::Value::MapValue options;
  // Since "clientPin" and "bioEnroll" are mutable, their bool is ignored.
  options[cbor::Value("up")] = cbor::Value(false);
  options[cbor::Value("rk")] = cbor::Value(true);
  options[cbor::Value("clientPin")] = cbor::Value(false);
  options[cbor::Value("bioEnroll")] = cbor::Value(true);

  device_tracker.Initialize(versions, extensions, options);
  EXPECT_TRUE(device_tracker.HasVersion("VERSION"));
  EXPECT_FALSE(device_tracker.HasVersion("WRONG_VERSION"));
  EXPECT_TRUE(device_tracker.HasExtension("EXTENSION"));
  EXPECT_FALSE(device_tracker.HasExtension("WRONG_EXTENSION"));
  EXPECT_FALSE(device_tracker.HasOption("up"));
  EXPECT_TRUE(device_tracker.HasOption("rk"));
  EXPECT_TRUE(device_tracker.HasOption("clientPin"));
  EXPECT_TRUE(device_tracker.HasOption("bioEnroll"));
}

TEST(DeviceTracker, TestAddObservation) {
  DeviceTracker device_tracker = DeviceTracker();
  device_tracker.AddObservation("OBSERVATION1");
  device_tracker.AddObservation("OBSERVATION2");
  testing::internal::CaptureStdout();
  device_tracker.ReportFindings();
  std::string output = testing::internal::GetCapturedStdout();
  std::string expected_output =
      "All counters were constant zero.\n\n"
      "OBSERVATION1\n"
      "OBSERVATION2\n"
      "\n\nPassed 0 out of 0 tests.\n";
  EXPECT_EQ(output, expected_output);
}

TEST(DeviceTracker, TestAddProblem) {
  DeviceTracker device_tracker = DeviceTracker();
  device_tracker.AddObservation("PROBLEM1");
  device_tracker.AddObservation("PROBLEM2");
  testing::internal::CaptureStdout();
  device_tracker.ReportFindings();
  std::string output = testing::internal::GetCapturedStdout();
  std::string expected_output =
      "All counters were constant zero.\n\n"
      "PROBLEM1\n"
      "PROBLEM2\n"
      "\n\nPassed 0 out of 0 tests.\n";
  EXPECT_EQ(output, expected_output);
}

TEST(DeviceTracker, TestCheckStatusOneArgument) {
  DeviceTracker device_tracker = DeviceTracker();
  testing::internal::CaptureStdout();
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrNone));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrOther));
  std::string output = testing::internal::GetCapturedStdout();
  std::string expected_output =
      "The failing error code is `CTAP1_ERR_OTHER`.\n";
  EXPECT_EQ(output, expected_output);
}

TEST(DeviceTracker, TestCheckStatusTwoArguments) {
  DeviceTracker device_tracker = DeviceTracker();
  testing::internal::CaptureStdout();
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrNone, Status::kErrNone));
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrOther, Status::kErrOther));
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrOther,
                                         Status::kErrInvalidCommand));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrOther, Status::kErrNone));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrNone, Status::kErrOther));
  std::string output = testing::internal::GetCapturedStdout();
  std::string output1 =
      "Expected error code `CTAP1_ERR_OTHER`, got "
      "`CTAP1_ERR_INVALID_COMMAND`.\n";
  std::string output2 =
      "Expected error code `CTAP1_ERR_OTHER`, got `CTAP2_OK`.\n";
  std::string output3 = "The failing error code is `CTAP1_ERR_OTHER`.\n";
  std::string expected_output = absl::StrCat(output1, output2, output3);
  EXPECT_EQ(output, expected_output);
}

TEST(DeviceTracker, TestCheckStatusVariant) {
  DeviceTracker device_tracker = DeviceTracker();
  testing::internal::CaptureStdout();
  absl::variant<cbor::Value, Status> value_variant = cbor::Value();
  EXPECT_TRUE(device_tracker.CheckStatus(value_variant));
  absl::variant<cbor::Value, Status> success_status_variant = Status::kErrNone;
  EXPECT_TRUE(device_tracker.CheckStatus(success_status_variant));
  absl::variant<cbor::Value, Status> fail_status_variant = Status::kErrOther;
  EXPECT_FALSE(device_tracker.CheckStatus(fail_status_variant));
  std::string output = testing::internal::GetCapturedStdout();
  std::string expected_output =
      "The failing error code is `CTAP1_ERR_OTHER`.\n";
  EXPECT_EQ(output, expected_output);
}

TEST(DeviceTracker, TestGenerateResultsJson) {
  DeviceTracker device_tracker = DeviceTracker();
  device_tracker.AddObservation("OBSERVATION");
  device_tracker.AddProblem("PROBLEM");
  device_tracker.LogTest("FALSE_TEST", "FALSE_DESCRIPTION", "ERROR_MESSAGE");
  device_tracker.LogTest("TRUE_TEST", "TRUE_DESCRIPTION", std::nullopt);

  nlohmann::json output =
      device_tracker.GenerateResultsJson("c0", "2020-01-01");
  nlohmann::json expected_output = {
      {"passed_test_count", 1},
      {"total_test_count", 2},
      {"failed_tests", {"FALSE_DESCRIPTION - ERROR_MESSAGE"}},
      {"problems", {"PROBLEM"}},
      {"observations", {"OBSERVATION"}},
      {"counter", "All counters were constant zero."},
      {"date", "2020-01-01"},
      {"commit", "c0"},
  };
  EXPECT_EQ(output, expected_output);
}

}  // namespace
}  // namespace fido2_tests

