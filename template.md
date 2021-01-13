{#-
  Copyright 2020 Google LLC

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-#}

## {{ device_under_test.product_name|default("Unknown", true) }}

{{ summary }}

### Failed tests:
{% if failed_tests %}
{%- for failed_test in failed_tests %}
* {{ failed_test.description }}
  * {{ failed_test.error_message }}
  {%- for observation in failed_test.observations %}
  * {{ observation }}
  {%- endfor %}
{%- endfor %}
{%- else %}
All tests passed!
{% endif %}

### Device capabilities

* HID
  * CBOR: {{ capabilities.cbor|default("false", true) }}
  * MSG : {{ capabilities.msg|default("false", true) }}
  * WINK: {{ capabilities.wink|default("false", true) }}
* Versions
  {%- for version in capabilities.versions %}
  * {{ version }}
  {%- endfor %}
* Options
  {%- for option in capabilities.options %}
  * {{ option }}
  {%- endfor %}
* Extensions
  {%- for extension in capabilities.extensions %}
  * {{ extension }}
  {%- endfor %}
* {{ capabilities.signature_counter|default("No signature counter information.", true) }}

### Device information

* Serial number: {{ device_under_test.serial_number|default("None", true) }}
* Manufacturer: {{ device_under_test.manufacturer|default("None", true) }}
* Vendor ID : {{ device_under_test.vendor_id|default("None", true) }}
* Product ID: {{ device_under_test.product_id|default("None", true) }}
* AAGUID: {{ device_under_test.aaguid|default("None", true) }}

