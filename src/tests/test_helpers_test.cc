// Copyright 2021 Google LLC
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

#include "src/tests/test_helpers.h"

#include "gtest/gtest.h"

namespace fido2_tests {
namespace {

TEST(TestHelpers, TestBadPin) {
  std::vector<uint8_t> pin = {'$', '$', '$', '$'};
  EXPECT_EQ(test_helpers::BadPin(4), pin);

  pin = {'$', '$', '$', '$', '$', '$'};
  EXPECT_EQ(test_helpers::BadPin(6), pin);
}

}  // namespace
}  // namespace fido2_tests

