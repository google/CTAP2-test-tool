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
    name = "monitor",
    srcs = ["monitor.cc"],
    hdrs = ["monitor.h"],
    deps = [
        "//:command_state",
        "//src/fuzzing:corpus_controller"
    ],
)

cc_library(
    name = "gdb_monitor",
    srcs = ["gdb_monitor.cc"],
    hdrs = ["gdb_monitor.h"],
    deps = [
        "//src/monitors:monitor",
        "//src/rsp:rsp"
    ],
)

cc_library(
    name = "cortexm4_gdb_monitor",
    srcs = ["cortexm4_gdb_monitor.cc"],
    hdrs = ["cortexm4_gdb_monitor.h"],
    deps = [
        "//src/monitors:gdb_monitor",
    ],
)

cc_library(
    name = "blackbox_monitor",
    srcs = ["blackbox_monitor.cc"],
    hdrs = ["blackbox_monitor.h"],
    deps = [
        "//:command_state",
        "//src/monitors:monitor",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "cortexm4_gdb_monitor_test",
    srcs = ["cortexm4_gdb_monitor_test.cc"],
    deps = [
        ":cortexm4_gdb_monitor",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_test(
    name = "gdb_monitor_test",
    srcs = ["gdb_monitor_test.cc"],
    deps = [
        ":gdb_monitor",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)
