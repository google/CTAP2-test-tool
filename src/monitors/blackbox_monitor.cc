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

#include "src/monitors/blackbox_monitor.h"

#include <iostream>

#include "absl/strings/str_cat.h"
#include "third_party/chromium_components_cbor/values.h"
#include "third_party/chromium_components_cbor/writer.h"

namespace fido2_tests {

bool BlackboxMonitor::Prepare(CommandState* command_state) {
  absl::variant<cbor::Value, Status> key_agreement_value =
      command_state->GetKeyAgreementValue();
  if (absl::holds_alternative<Status>(key_agreement_value)) {
    return false;
  }
  initial_key_agreement_ =
      std::move(absl::get<cbor::Value>(key_agreement_value));
  return true;
}

std::tuple<bool, std::vector<std::string>> BlackboxMonitor::DeviceCrashed(
    CommandState* command_state, int retries) {
  Status status = Status::kErrNone;
  cbor::Value new_key_agreement;
  std::vector<std::string> observations;
  for (int i = 0; i < retries; ++i) {
    absl::variant<cbor::Value, Status> key_agreement_value =
        command_state->GetKeyAgreementValue();
    if (absl::holds_alternative<Status>(key_agreement_value)) {
      status = absl::get<Status>(key_agreement_value);
      observations.push_back(absl::StrCat("GetKeyAgreement got error code - ",
                                          StatusToString(status)));
    } else {
      new_key_agreement =
          std::move(absl::get<cbor::Value>(key_agreement_value));
      break;
    }
  }
  return {status != Status::kErrNone ||
              cbor::Writer::Write(new_key_agreement) !=
                  cbor::Writer::Write(initial_key_agreement_),
          observations};
}

}  // namespace fido2_tests

