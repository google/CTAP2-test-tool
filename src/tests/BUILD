# Copyright 2019-2021 Google LLC
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
    srcs = ["test_series.cc"],
    hdrs = ["test_series.h"],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//src/tests:base",
        "//src/tests:client_pin",
        "//src/tests:general",
        "//src/tests:get_assertion",
        "//src/tests:make_credential",
        "//src/tests:reset",
        "//src/tests:fuzzing_corpus",
        "//src/monitors:monitor",
        "//third_party/chromium_components_cbor:cbor",
    ],
)

COMMON_TEST_DEPS = [
    "//:cbor_builders",
    "//:command_state",
    "//:constants",
    "//:crypto_utility",
    "//:device_interface",
    "//:device_tracker",
    "//:fido2_commands",
    "//src/tests:base",
    "//src/tests:test_helpers",
    "//third_party/chromium_components_cbor:cbor",
    "@com_google_absl//absl/strings",
    "@com_google_absl//absl/types:variant",
]

cc_library(
    name = "fuzzing_corpus",
    srcs = ["fuzzing_corpus.cc"],
    hdrs = ["fuzzing_corpus.h"],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//src/monitors:monitor",
        "//src/tests:base",
    ],
)

cc_library(
    name = "client_pin",
    srcs = ["client_pin.cc"],
    hdrs = ["client_pin.h"],
    deps = COMMON_TEST_DEPS,
)

cc_library(
    name = "general",
    srcs = ["general.cc"],
    hdrs = ["general.h"],
    deps = COMMON_TEST_DEPS,
)

cc_library(
    name = "get_assertion",
    srcs = ["get_assertion.cc"],
    hdrs = ["get_assertion.h"],
    deps = COMMON_TEST_DEPS,
)

cc_library(
    name = "make_credential",
    srcs = ["make_credential.cc"],
    hdrs = ["make_credential.h"],
    deps = COMMON_TEST_DEPS,
)

cc_library(
    name = "reset",
    srcs = ["reset.cc"],
    hdrs = ["reset.h"],
    deps = COMMON_TEST_DEPS,
)

cc_library(
    name = "base",
    srcs = ["base.cc"],
    hdrs = ["base.h"],
    deps = [
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
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
    deps = [
        "//:cbor_builders",
        "//:command_state",
        "//:device_interface",
        "//:device_tracker",
        "//:fido2_commands",
        "//third_party/chromium_components_cbor:cbor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time:time",
        "@com_google_absl//absl/types:variant",
        "@com_google_glog//:glog",
    ],
)

cc_test(
    name = "test_helpers_test",
    srcs = ["test_helpers_test.cc"],
    deps = [
        ":test_helpers",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)
