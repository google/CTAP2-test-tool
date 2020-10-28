#!/usr/bin/env bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script runs the fuzzing tool with a predefined corpus located at the
# relative path "corpus_tests/test_corpus/", using a black box monitor.
# To provide a custom corpus or change the monitor, please run 
# `bazel run //:corpus_test` with the desired arguments.

# The underscore is the magic path that uses the first device found. You can
# also pass the desired path as a command line argument.
path=${1:-_}
bazel run //:corpus_test -- --token_path="$path"
