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

#include "src/tests/base.h"

namespace fido2_tests {

BaseTest::BaseTest(std::string test_id, std::string test_description,
                   Preconditions preconditions, absl::flat_hash_set<Tag> tags)
    : test_id_(std::move(test_id)),
      test_description_(std::move(test_description)),
      preconditions_(std::move(preconditions)),
      tags_(std::move(tags)) {}

void BaseTest::Setup(CommandState* command_state) const {
  command_state->Prepare(preconditions_.has_pin);
}

std::string BaseTest::GetId() const { return test_id_; }

std::string BaseTest::GetDescription() const { return test_description_; }

bool BaseTest::HasTag(Tag tag) const { return tags_.contains(tag); }

}  // namespace fido2_tests

