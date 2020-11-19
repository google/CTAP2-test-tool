# Copyright 2020 Google LLC
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

"""This script converts JSON result files to Markdown summaries.

The JSON format is meant to contain all details from tests. For human readable
outputs, use this script to extract the most interest information from your JSON
reports and write them into an eye-friendly markdown file.

  Typical usage example:

  python convert_results.py --source=results/ --target=result_summaries/
"""

import argparse
import json
import os
from tabulate import tabulate


def summary_table(tests, passed_test_count, total_test_count):
  """Returns a Markdown table summing passed tests for all tags."""
  tags = {}
  for test in tests:
    pass_score = 1 if test['result'] == 'pass' else 0
    for tag in test.get('tags', []):
      if tag in tags:
        tags[tag][0] += pass_score
        tags[tag][1] += 1
      else:
        tags[tag] = [pass_score, 1]

  headers = ['Category', 'Passed', 'Total']
  table = [['All', passed_test_count, total_test_count]]
  for tag, counts in tags.items():
    table.append([tag] + counts)
  return tabulate(table, headers, tablefmt='github')


def convert_bulleted_list(value):
  """Maps list entries from string to indented Markdown list entries."""
  if not isinstance(value, list):
    value = []
  return ['  * {}'.format(entry) for entry in value]


def test_to_string(test):
  """Returns a list of lines in a Markdown file for the given test."""
  entries = []
  description = test.get('description', 'Unnamed test.')
  entries.append('* {}'.format(description))
  error_message = test.get('error_message', 'No error message.')
  entries.append('  * {}'.format(error_message))
  observations = test.get('observations', [])
  entries += convert_bulleted_list(observations)
  return '\n'.join(entries)


def capabilities_to_text(capabilities):
  """Returns a list of lines in a Markdown file for the given capabilities."""
  entries = []
  entries.append('* HID')
  cbor = capabilities.get('cbor', False)
  entries.append('  * CBOR: {}'.format(cbor))
  msg = capabilities.get('msg', False)
  entries.append('  * MSG : {}'.format(msg))
  wink = capabilities.get('wink', False)
  entries.append('  * WINK: {}'.format(wink))

  versions = capabilities.get('versions', [])
  if versions:
    entries.append('* Versions')
  entries += convert_bulleted_list(versions)

  options = capabilities.get('options', [])
  if options:
    entries.append('* Options')
  entries += convert_bulleted_list(options)

  extensions = capabilities.get('extensions', [])
  if extensions:
    entries.append('* Extensions')
  entries += convert_bulleted_list(extensions)

  signature_counter = capabilities.get('signature_counter',
                                       'No signature counter information.')
  entries.append('* {}'.format(signature_counter))
  return '\n'.join(entries)


def convert(result):
  """Converts the result file JSON content to Markdown file content."""
  try:
      result = json.loads(result)
  except ValueError as _:
    print('File was not valid JSON.')
    return ''

  for key in ['capabilities', 'device_under_test', 'tests']:
    if key not in result:
      print('JSON was missing the mandatory key {}.'.format(key))
      return ''

  tests = result['tests']
  for test in tests:
    if 'result' not in test:
      test['result'] = 'fail'

  device_under_test = result['device_under_test']
  product_name = device_under_test.get('product_name', 'Unknown')
  serial_number = device_under_test.get('serial_number', 'None')
  manufacturer = device_under_test.get('manufacturer', 'None')
  vendor_id = device_under_test.get('vendor_id', 'None')
  product_id = device_under_test.get('product_id', 'None')
  aaguid = device_under_test.get('aaguid', 'None')
  device_info = [serial_number, manufacturer, vendor_id, product_id, aaguid]

  passed = sum(1 if test['result'] == 'pass' else 0 for test in tests)
  passed_test_count = result.get('passed_test_count', passed)
  total_test_count = result.get('total_test_count', len(tests))
  summary = summary_table(tests, passed_test_count, total_test_count)

  failed_tests = []
  for test in tests:
    if test['result'] == 'fail':
      failed_tests.append(test_to_string(test))
  failed_test_text = '\n'.join(failed_tests)

  capabilities = capabilities_to_text(result['capabilities'])

  text = '''## {}

{}

### Failed tests:

{}

### Device capabilities

{}

### Device information

* Serial number: {}
* Manufacturer: {}
* Vendor ID : {}
* Product ID: {}
* AAGUID: {}
'''.format(product_name, summary, failed_test_text, capabilities, *device_info)
  return text


def main(args):
  """Converts all JSON file from the source directory to Markdown."""
  if os.path.exists(args.target_dir):
    print('Directory', args.target_dir, 'exists already, files may be overwritten.')
  else:
    os.mkdir(args.target_dir)
  for json_file in os.listdir(args.source_dir):
    sk_name, extension = os.path.splitext(json_file)
    if extension == '.json':
      print('Converting', sk_name, '...')
      with open(os.path.join(args.source_dir, json_file), 'r') as source_file:
        json_text = source_file.read()
      with open(os.path.join(args.target_dir, sk_name + '.md'), 'w') as target_file:
        target_file.write(convert(json_text))


if __name__ == '__main__':
  main_parser = argparse.ArgumentParser()
  main_parser.add_argument(
      "--source",
      default='results/',
      dest="source_dir",
      help=("Directory containing all JSON files."),
  )
  main_parser.add_argument(
      "--target",
      default='result_summaries/',
      dest="target_dir",
      help=("Directory for storing all Markdown files."),
  )
  main(main_parser.parse_args())

