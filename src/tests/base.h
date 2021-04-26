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

#ifndef TESTS_BASE_H_
#define TESTS_BASE_H_

#include "absl/container/flat_hash_set.h"
#include "src/command_state.h"
#include "src/device_interface.h"
#include "src/device_tracker.h"

namespace fido2_tests {

// Contains information about the device state a test requires to run correctly.
struct Preconditions {
  bool has_pin;
};

// Describes what features a test uses. Can be used to filter tests or display
// results grouped by tag.
enum class Tag { kClientPin, kFido2Point1, kFuzzing, kHmacSecret };

// Returns a readable name for each tag.
std::string TagToString(Tag tag);

// All tests inherit this base class to have the same interface to run them.
// Run tests by first calling Setup, then Execute.
class BaseTest {
 public:
  // A subclass is expected to pass in values describing its properties.
  BaseTest(std::string test_id, std::string test_description,
           Preconditions preconditions, absl::flat_hash_set<Tag> tags);
  virtual ~BaseTest() = default;
  // Executes the test code. Returns std::nullopt if the test was successful, or
  // an error message if it failed. As a side effect, it can change the device
  // and command state. Also, more information can be logged in device_tracker.
  virtual std::optional<std::string> Execute(
      DeviceInterface* device, DeviceTracker* device_tracker,
      CommandState* command_state) const = 0;
  // Adjusts comand_state to match the preconditions.
  virtual void Setup(CommandState* command_state) const;
  // Gets the test ID.
  std::string GetId() const;
  // Gets the test description.
  std::string GetDescription() const;
  // Checks if the test has a specific tag.
  bool HasTag(Tag tag) const;
  // Returns a list of all tags.
  std::vector<std::string> ListTags() const;
  // Generates an example relying party ID for tests. It is best practise to use
  // this RP ID outside of special tests to have less interference between
  // tests. The returned value is consistent between calls and unique for a test
  // ID.
  std::string RpId() const;

 private:
  const std::string test_id_;
  const std::string test_description_;
  const Preconditions preconditions_;
  const absl::flat_hash_set<Tag> tags_;
};

// This convenience macro defines a test subclass to make headers more readable.
#define TEST_CLASS(name)                                        \
  class name : public BaseTest {                                \
   public:                                                      \
    name();                                                     \
    std::optional<std::string> Execute(                         \
        DeviceInterface* device, DeviceTracker* device_tracker, \
        CommandState* command_state) const override;            \
  }

}  // namespace fido2_tests

#endif  // TESTS_BASE_H_

