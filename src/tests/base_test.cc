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

#include "src/tests/base.h"

#include "gtest/gtest.h"

namespace fido2_tests {
namespace {

TEST_CLASS(ExampleTest);
ExampleTest::ExampleTest()
    : BaseTest("example", "Tests nothing.", Preconditions{false},
               {Tag::kClientPin}) {}

std::optional<std::string> ExampleTest::Execute(
    DeviceInterface* device, DeviceTracker* device_tracker,
    CommandState* command_state) const {
  return std::nullopt;
}

TEST(DeviceTracker, TestExampleSubclass) {
  ExampleTest example_test = ExampleTest();
  EXPECT_EQ(example_test.Execute(nullptr, nullptr, nullptr), std::nullopt);
  EXPECT_EQ(example_test.GetId(), "example");
  EXPECT_EQ(example_test.GetDescription(), "Tests nothing.");
  EXPECT_TRUE(example_test.HasTag(Tag::kClientPin));
  EXPECT_FALSE(example_test.HasTag(Tag::kFido2Point1));
  EXPECT_EQ(example_test.RpId(), "example.example.com");
  EXPECT_EQ(example_test.ListTags(),
            std::vector<std::string>({TagToString(Tag::kClientPin)}));
}

}  // namespace
}  // namespace fido2_tests

