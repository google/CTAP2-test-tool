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

#include "src/tests/base.h"

#include "absl/strings/str_cat.h"

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

std::string TagToString(Tag tag) {
  switch (tag) {
    case Tag::kClientPin:
      return "Client PIN";
    case Tag::kFido2Point1:
      return "FIDO 2.1";
    case Tag::kFuzzing:
      return "Fuzzing";
    case Tag::kHmacSecret:
      return "HMAC Secret";
    default:
      CHECK(false) << "unreachable default - TEST SUITE BUG";
  }
}

std::string BaseTest::GetId() const { return test_id_; }

std::string BaseTest::GetDescription() const { return test_description_; }

bool BaseTest::HasTag(Tag tag) const { return tags_.contains(tag); }

std::vector<std::string> BaseTest::ListTags() const {
  std::vector<std::string> tag_list;
  tag_list.reserve(tags_.size());
  for (Tag tag : tags_) {
    tag_list.push_back(TagToString(tag));
  }
  return tag_list;
}

std::string BaseTest::RpId() const {
  return absl::StrCat(test_id_, ".example.com");
}

}  // namespace fido2_tests

