# Copyright 2020-2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "fuzzing_helpers",
    srcs = ["fuzzing_helpers.cc"],
    hdrs = ["fuzzing_helpers.h"],
    deps = ["//:device_interface"],
)

cc_library(
    name = "corpus_controller",
    srcs = ["corpus_controller.cc"],
    hdrs = ["corpus_controller.h"],
    deps = [
        ":fuzzing_helpers",
        "//:device_interface",
        "@com_google_glog//:glog"
    ],
)

cc_library(
    name = "mutator",
    srcs = ["mutator.cc"],
    hdrs = ["mutator.h"],
    deps = [
        "@com_google_glog//:glog",
    ]
)

cc_library(
    name = "fuzzer",
    srcs = ["fuzzer.cc"],
    hdrs = ["fuzzer.h"],
    deps = [
        ":corpus_controller",
        ":fuzzing_helpers",
        ":mutator",
        "//:command_state",
        "//:hid_device",
        "//src/monitors:monitor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ]
)

cc_test(
    name = "mutator_test",
    srcs = ["mutator_test.cc"],
    deps = [
        ":mutator",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)
