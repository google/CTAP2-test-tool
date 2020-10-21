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

#ifndef TESTS_BASE_H_
#define TESTS_BASE_H_

#include "absl/container/flat_hash_set.h"
#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"

namespace fido2_tests {

struct Preconditions {
  bool has_pin;
};

enum class Tag { kClientPin, kFido2Point1 };

class BaseTest {
 public:
  BaseTest(std::string test_id, std::string test_description,
           Preconditions preconditions, absl::flat_hash_set<Tag> tags);
  virtual ~BaseTest() = default;
  virtual std::optional<std::string> Execute(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state) const = 0;
  // Adjusts comand_state to match the preconditions.
  void Setup(CommandState* command_state) const;
  // Gets the test ID.
  std::string GetId() const;
  // Gets the test description.
  std::string GetDescription() const;
  // Checks if the test has a specific tag.
  bool HasTag(Tag tag) const;

 private:
  std::string test_id_;
  std::string test_description_;
  Preconditions preconditions_;
  absl::flat_hash_set<Tag> tags_;
};

#define TEST_CLASS(name)                                        \
  class name : public BaseTest {                                \
   public:                                                      \
    name();                                                     \
    std::optional<std::string> Execute(                         \
        DeviceInterface* device, DeviceTracker* device_tracker, \
        CommandState* command_state) const override;            \
  };

}  // namespace fido2_tests

#endif  // TESTS_BASE_H_
