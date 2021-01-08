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

  python convert_results.py --source=results/ --output=results/summaries/
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path

import jinja2
from tabulate import tabulate
from tqdm.auto import tqdm


def summary_table(tests):
  """Creates a Markdown table summarizing passed tests for all tags.

    Args:
      tests: A list of tests, that have a 'result' entry, and possibly 'tags'.
        The value of 'result' is 'pass' for a passing test.
        If a test contains the key 'tags', it must be a list of strings.

    Returns:
      A string with a summary table in Markdown.
  """
  tags = defaultdict(lambda: defaultdict(int))
  for test in tests:
    # The 'All' tag is added to count all test results.
    for tag in test.get('tags', []) + ['All']:
      if test['result'] == 'pass':
        tags[tag]['pass'] += 1
      tags[tag]['total'] += 1

  headers = ['Category', 'Passed', 'Total']
  table = []
  for tag, counts in tags.items():
    table.append([tag, counts['pass'], counts['total']])
  return tabulate(table, headers, tablefmt='github')


def convert(result, template_file='template.md'):
  """Converts the result file JSON content to a Markdown text.

    Args:
      result: A string with the content of a JSON file output by the test tool.
      template_file: Markdown template for jinja.

    Returns:
      A string with the text of a Markdown file.
  """
  try:
    result = json.loads(result)
  except ValueError as _:
    print('File is not valid JSON.')
    return ''

  for key in ['capabilities', 'device_under_test', 'tests']:
    if key not in result:
      print('JSON was missing the mandatory key {}.'.format(key))
      return ''

  capabilities = result['capabilities']
  device_under_test = result['device_under_test']
  tests = result['tests']
  for test in tests:
    if 'result' not in test:
      test['result'] = 'fail'
  failed_tests = [test for test in tests if test['result'] == 'fail']
  summary = summary_table(tests)

  loader = jinja2.FileSystemLoader(searchpath='./')
  env = jinja2.Environment(loader=loader)
  template = env.get_template(template_file)
  return template.render(capabilities=capabilities,
                         device_under_test=device_under_test,
                         failed_tests=failed_tests,
                         summary=summary)


def main(args):
  """Converts all JSON files from the source directory to Markdown."""
  output_path = Path(args.output_dir)
  if output_path.exists():
    print('Directory', args.output_dir, 'exists, files may be overwritten.')
  else:
    output_path.mkdir(parents=True)

  paths = list(Path(args.source_dir).glob('*.json'))
  progress_bar = tqdm(total=len(paths), unit='files')
  for path in paths:
    progress_bar.update()
    output_file = output_path / path.with_suffix('.md').name
    json_text = path.read_text()
    output_file.write_text(convert(json_text))


if __name__ == '__main__':
  main_parser = argparse.ArgumentParser()
  main_parser.add_argument(
      '--source',
      default='results/',
      dest='source_dir',
      help=('Directory containing the test result files in JSON.'),
  )
  main_parser.add_argument(
      '--output',
      default='results/summaries/',
      dest='output_dir',
      help=('Directory for writing the converted Markdown files.'),
  )
  main(main_parser.parse_args())
