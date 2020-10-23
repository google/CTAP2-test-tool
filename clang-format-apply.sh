# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runs clang-format and apply changes.

alias clang-format=clang-format-9

clang-format --version

# Recursively covers the same paths as clang-format-show-diff.sh. Breaks on
# whitespace.
for FILE in $(find . -name '*.h' -o -name '*.cc' -o \
                     -path './third_party' -prune -false); do
  # Run clang-format, then append a newline.
  clang-format --verbose -i "${FILE}"
  echo "" >> "${FILE}"
done

