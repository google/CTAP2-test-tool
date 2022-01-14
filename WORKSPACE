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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

http_archive(
    name = "com_google_absl",
    sha256 = "b4e20d9e752a75c10636675691b1e9c2698e0764cb404987d0ffa77223041c19",
    urls = ["https://github.com/abseil/abseil-cpp/archive/215105818dfde3174fe799600bb0f3cae233d0bf.zip"],
    strip_prefix = "abseil-cpp-215105818dfde3174fe799600bb0f3cae233d0bf",
)

http_archive(
    name = "com_github_nlohmann_json",
    sha256 = "6bea5877b1541d353bd77bdfbdb2696333ae5ed8f9e8cc22df657192218cad91",
    urls = [
        "https://github.com/nlohmann/json/releases/download/v3.9.1/include.zip",
    ],
    build_file = "@//:third_party/BUILD.nlohmann_json",
)

git_repository(
    name = "boringssl",
    commit = "822fefaebe545071599f69278102cbc645345f7b",
    remote = "https://boringssl.googlesource.com/boringssl",
)

git_repository(
    name = "com_github_gflags_gflags",
    commit = "2e227c3daae2ea8899f49858a23f3d318ea39b57",
    remote = "https://github.com/gflags/gflags",
)

git_repository(
    name = "com_google_glog",
    commit = "195d416e3b1c8dc06980439f6acd3ebd40b6b820",
    remote = "https://github.com/google/glog",
)

git_repository(
    name = "com_google_googletest",
    commit = "23b2a3b1cf803999fb38175f6e9e038a4495c8a5",
    remote = "https://github.com/google/googletest",
)

new_git_repository(
    name = "com_github_kaczmarczyck_hidapi",
    commit = "6061c92bf40056062dae7378515490104cee3344",
    remote = "https://github.com/kaczmarczyck/hidapi",
    build_file = "@//:BUILD.hidapi",
)

local_repository(
    name = "chromium_components_cbor",
    path = "third_party/chromium_components_cbor",
)

