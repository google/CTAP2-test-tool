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
  cbor::Value::MapValue info;
  info[CborInt(InfoMember::kVersions)] = cbor::Value(versions);
  info[CborInt(InfoMember::kExtensions)] = cbor::Value(extensions);
  info[CborInt(InfoMember::kOptions)] = cbor::Value(options);

  device_tracker.Initialize(info);
  EXPECT_TRUE(device_tracker.HasVersion("VERSION"));
  EXPECT_FALSE(device_tracker.HasVersion("WRONG_VERSION"));
  EXPECT_TRUE(device_tracker.HasExtension("EXTENSION"));
  EXPECT_FALSE(device_tracker.HasExtension("WRONG_EXTENSION"));
  EXPECT_FALSE(device_tracker.HasOption("up"));
  EXPECT_TRUE(device_tracker.HasOption("rk"));
  EXPECT_TRUE(device_tracker.HasOption("clientPin"));
  EXPECT_TRUE(device_tracker.HasOption("bioEnroll"));
}

TEST(DeviceTracker, TestInitializeDefault) {
  DeviceTracker device_tracker = DeviceTracker();
  cbor::Value::ArrayValue versions;
  cbor::Value::MapValue info;
  info[CborInt(InfoMember::kVersions)] = cbor::Value(versions);

  device_tracker.Initialize(info);
  EXPECT_TRUE(device_tracker.HasOption("up"));
}

TEST(DeviceTracker, TestGetMinPinLength) {
  DeviceTracker device_tracker = DeviceTracker();
  EXPECT_EQ(device_tracker.GetMinPinLength(), 4);

  cbor::Value::ArrayValue versions;
  cbor::Value::MapValue info;
  info[CborInt(InfoMember::kVersions)] = cbor::Value(versions);
  info[CborInt(InfoMember::kMinPinLength)] = cbor::Value(6);
  device_tracker.Initialize(info);
  EXPECT_EQ(device_tracker.GetMinPinLength(), 6);
}

TEST(DeviceTracker, TestCheckStatusOneArgument) {
  DeviceTracker device_tracker = DeviceTracker();
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrNone));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrOther));
}

TEST(DeviceTracker, TestCheckStatusTwoArguments) {
  DeviceTracker device_tracker = DeviceTracker();
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrNone, Status::kErrNone));
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrOther, Status::kErrOther));
  EXPECT_TRUE(device_tracker.CheckStatus(Status::kErrOther,
                                         Status::kErrInvalidCommand));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrOther, Status::kErrNone));
  EXPECT_FALSE(device_tracker.CheckStatus(Status::kErrNone, Status::kErrOther));
}

TEST(DeviceTracker, TestCheckStatusVariant) {
  DeviceTracker device_tracker = DeviceTracker();
  absl::variant<cbor::Value, Status> value_variant = cbor::Value();
  EXPECT_TRUE(device_tracker.CheckStatus(value_variant));
  absl::variant<cbor::Value, Status> success_status_variant = Status::kErrNone;
  EXPECT_TRUE(device_tracker.CheckStatus(success_status_variant));
  absl::variant<cbor::Value, Status> fail_status_variant = Status::kErrOther;
  EXPECT_FALSE(device_tracker.CheckStatus(fail_status_variant));
}

TEST(DeviceTracker, TestGenerateResultsJson) {
  DeviceTracker device_tracker = DeviceTracker();
  cbor::Value::ArrayValue versions;
  versions.push_back(cbor::Value("VERSION"));
  cbor::Value::ArrayValue extensions;
  extensions.push_back(cbor::Value("EXTENSION"));
  cbor::Value::MapValue options;
  options[cbor::Value("up")] = cbor::Value(true);
  cbor::Value::MapValue info;
  info[CborInt(InfoMember::kVersions)] = cbor::Value(versions);
  info[CborInt(InfoMember::kExtensions)] = cbor::Value(extensions);
  info[CborInt(InfoMember::kOptions)] = cbor::Value(options);

  device_tracker.Initialize(info);
  device_tracker.SetDeviceIdentifiers({.manufacturer = "M",
                                       .product_name = "P",
                                       .serial_number = "S",
                                       .vendor_id = 1,
                                       .product_id = 2});
  device_tracker.SetAaguid("ABCD0123");
  device_tracker.SetCapabilities(/*wink=*/true, /*cbor=*/true, /*msg=*/false);
  device_tracker.AddObservation("OBSERVATION");
  device_tracker.LogTest("FALSE_TEST", "FALSE_DESCRIPTION", "ERROR_MESSAGE",
                         {});
  device_tracker.LogTest("TRUE_TEST", "TRUE_DESCRIPTION", std::nullopt,
                         {"TAG"});

  nlohmann::json output =
      device_tracker.GenerateResultsJson("c0", "2020-01-01");
  nlohmann::json expected_output = {
      {"passed_test_count", 1},
      {"total_test_count", 2},
      {"tests", nlohmann::json::array({
                    {
                        {"id", "FALSE_TEST"},
                        {"description", "FALSE_DESCRIPTION"},
                        {"result", "fail"},
                        {"error_message", "ERROR_MESSAGE"},
                        {"observations", {"OBSERVATION"}},
                        {"tags", nlohmann::json::array()},
                    },
                    {
                        {"id", "TRUE_TEST"},
                        {"description", "TRUE_DESCRIPTION"},
                        {"result", "pass"},
                        {"error_message", nullptr},
                        {"observations", nlohmann::json::array()},
                        {"tags", {"TAG"}},
                    },
                })},
      {"date", "2020-01-01"},
      {"commit", "c0"},
      {
          "device_under_test",
          {
              {"manufacturer", "M"},
              {"product_name", "P"},
              {"serial_number", "S"},
              {"vendor_id", "0x0001"},
              {"product_id", "0x0002"},
              {"aaguid", "ABCD0123"},
              {"url", nullptr},
          },
      },
      {"transport_used", "HID"},
      {
          "capabilities",
          {
              {"versions", {"VERSION"}},
              {"options", {"up"}},
              {"extensions", {"EXTENSION"}},
              {"wink", true},
              {"cbor", true},
              {"msg", false},
              {"signature_counter", "All counters were constant zero."},
          },
      },
  };
  EXPECT_EQ(output, expected_output);
}

}  // namespace
}  // namespace fido2_tests

