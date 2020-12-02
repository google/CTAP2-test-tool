# Copyright 2019 Google LLC
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

# Test suite for FIDO 2 authenticators

package(default_visibility = ["//visibility:public"])

# Windows is untested so far.
cc_library(
    name = "hid_device",
    srcs = ["src/hid/hid_device.cc"],
    hdrs = ["src/hid/hid_device.h"],
    deps = [
        ":constants",
        ":device_interface",
        ":device_tracker",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_glog//:glog",
    ] + select({
        "@bazel_tools//src/conditions:darwin": ["@com_github_kaczmarczyck_hidapi//:hidapi-osx"],
        "@bazel_tools//src/conditions:windows": ["@com_github_kaczmarczyck_hidapi//:hidapi-libusb"],
        "//conditions:default": ["@com_github_kaczmarczyck_hidapi//:hidapi-linux"],
    }),
)

cc_library(
    name = "device_interface",
    hdrs = ["src/device_interface.h"],
    deps = [":constants"],
)

cc_library(
    name = "cbor_builders",
    srcs = ["src/cbor_builders.cc"],
    hdrs = ["src/cbor_builders.h"],
    deps = [
        ":constants",
        ":crypto_utility",
        "//third_party/chromium_components_cbor:cbor",
    ],
)

cc_test(
    name = "cbor_builders_test",
    srcs = ["src/cbor_builders_test.cc"],
    deps = [
        ":cbor_builders",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "constants",
    srcs = ["src/constants.cc"],
    hdrs = ["src/constants.h"],
    deps = [
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_glog//:glog",
    ],
)

cc_library(
    name = "crypto_utility",
    srcs = ["src/crypto_utility.cc"],
    hdrs = ["src/crypto_utility.h"],
    deps = [
        ":constants",
        "//third_party/chromium_components_cbor:cbor",
        "@boringssl//:crypto",
        "@com_google_glog//:glog",
    ],
)

cc_library(
    name = "device_tracker",
    srcs = ["src/device_tracker.cc"],
    hdrs = ["src/device_tracker.h"],
    deps = [
        ":constants",
        ":device_interface",
        ":parameter_check",
        ":stamp",
        "//third_party/chromium_components_cbor:cbor",
        "@com_github_nlohmann_json//:json",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "device_tracker_test",
    srcs = ["src/device_tracker_test.cc"],
    deps = [
        ":device_tracker",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "fido2_commands",
    srcs = ["src/fido2_commands.cc"],
    hdrs = ["src/fido2_commands.h"],
    deps = [
        ":constants",
        ":crypto_utility",
        ":device_interface",
        ":device_tracker",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:variant",
        "@com_google_glog//:glog",
        "@boringssl//:crypto",
    ],
)

cc_library(
    name = "command_state",
    srcs = ["src/command_state.cc"],
    hdrs = ["src/command_state.h"],
    deps = [
        ":constants",
        ":crypto_utility",
        ":cbor_builders",
        ":device_interface",
        ":device_tracker",
        ":fido2_commands",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:variant",
        "@com_google_glog//:glog",
    ],
)

cc_library(
    name = "parameter_check",
    srcs = ["src/parameter_check.cc"],
    hdrs = ["src/parameter_check.h"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_glog//:glog",
    ],
)

cc_library(
    name = "stamp",
    linkstamp = "src/stamp.cc"
)

cc_binary(
    name = "fido2_conformance",
    srcs = ["src/fido2_conformance_main.cc"],
    deps = [
        ":command_state",
        ":device_tracker",
        ":hid_device",
        ":parameter_check",
        "//src/tests:test_series",
        "@com_github_gflags_gflags//:gflags",
        "@com_google_glog//:glog",
    ],
)

cc_binary(
    name = "corpus_test",
    srcs = ["src/corpus_test_main.cc"],
    deps = [
        ":command_state",
        ":constants",
        ":hid_device",
        "//src/fuzzing:corpus_controller",
        "//src/monitors:blackbox_monitor",
        "//src/monitors:cortexm4_gdb_monitor",
        "//src/monitors:gdb_monitor",
        "//src/tests:test_series",
        "//src/tests:base",
        "@com_github_gflags_gflags//:gflags",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_glog//:glog",
    ],
)

cc_binary(
    name = "fuzzing",
    srcs = ["src/fuzzing_main.cc"],
    deps = [
        ":command_state",
        ":constants",
        ":hid_device",
        "//src/fuzzing:fuzzer",
        "//src/fuzzing:fuzzing_helpers",
        "//src/monitors:blackbox_monitor",
        "//src/monitors:cortexm4_gdb_monitor",
        "//src/monitors:gdb_monitor",
        "@com_github_gflags_gflags//:gflags",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_glog//:glog",
    ],
)
