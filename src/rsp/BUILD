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
    name = "rsp_packet",
    srcs = ["rsp_packet.cc"],
    hdrs = ["rsp_packet.h"],
    deps = ["@com_google_absl//absl/strings"]
)

cc_test(
    name = "rsp_packet_test",
    srcs = ["rsp_packet_test.cc"],
    deps = [
        ":rsp_packet",
        "@com_google_googletest//:gtest_main",
    ],
    size = "small",
)

cc_library(
    name = "rsp",
    srcs = ["rsp.cc"],
    hdrs = ["rsp.h"],
    deps = [
        ":rsp_packet",
        "@com_google_glog//:glog",
    ]
)
