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

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "test_series",
    srcs = [
        "test_client_pin.cc",
        "test_series.cc",
        "test_get_assertion.cc",
        "test_make_credential.cc",
    ],
    hdrs = ["test_series.h"],
    copts = [
        "-Wno-return-type",
    ],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//src/tests:base",
        "//src/tests:general",
        "//src/tests:reset",
        "//third_party/chromium_components_cbor:cbor",
    ],
)

cc_library(
    name = "general",
    srcs = ["general.cc"],
    hdrs = ["general.h"],
    copts = [
        "-Wno-return-type",
    ],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//:fido2_commands",
        "//src/tests:base",
        "//src/tests:test_helpers",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "reset",
    srcs = ["reset.cc"],
    hdrs = ["reset.h"],
    copts = [
        "-Wno-return-type",
    ],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//:fido2_commands",
        "//src/tests:base",
        "//src/tests:test_helpers",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "base",
    srcs = ["base.cc"],
    hdrs = ["base.h"],
    copts = [
        "-Wno-return-type",
    ],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

cc_test(
    name = "base_test",
    srcs = ["base_test.cc"],
    deps = [
        ":base",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "test_helpers",
    srcs = ["test_helpers.cc"],
    hdrs = ["test_helpers.h"],
    copts = [
        "-Wno-return-type",
    ],
    deps = [
        "//:cbor_builders",
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//:fido2_commands",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
        "@com_google_glog//:glog",
    ],
)

