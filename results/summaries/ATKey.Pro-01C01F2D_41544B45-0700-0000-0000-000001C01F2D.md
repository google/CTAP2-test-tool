## ATKey.Pro-01C01F2D

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       67 |      74 |
| Client PIN  |       38 |      40 |
| FIDO 2.1    |        7 |       8 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests entries in the credential parameters list.
  * Falsely rejected cred params list with 1 good and 1 bad element.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_ALGORITHM`.
* Tests if non-ASCII display name are accepted.
  * Failed on displayName with non-ASCII characters.
  * The failing error code is `CTAP2_ERR_KEY_STORE_FULL`.
* Tests if invalid UTF8 is caught in displayName.
  * UTF-8 correctness is not checked.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests if the resident key option is rejected in GetAssertion.
  * The resident key option (false) was not rejected.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_OPTION`, got `CTAP2_OK`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * GetAssertion failed with PIN protocol, but without a token when PIN is set.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_PIN_AUTH_INVALID`.
* Tests if empty user IDs are omitted in the response.
  * Cannot make credential with an empty user ID.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_PROCESSING`.
* Tests if PIN auth attempts are blocked correctly.
  * The correct PIN is not blocked when auth is blocked.
  * Expected error code `CTAP2_ERR_PIN_AUTH_BLOCKED`, got `CTAP2_OK`.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * FIDO_2_0
  * FIDO_2_1_PRE
  * U2F_V2
* Options
  * up
  * clientPin
  * uv
  * rk
  * bioEnroll
  * platConfig
  * credMgmt
  * setMinPINLength
  * uvToken
* Extensions
  * credProtect
  * hmac-secret
  * credBlob
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: 41544B45-0700-0000-0000-000001C01F2D
* Manufacturer: AuthenTrend Technology Inc.
* Vendor ID : 0x31bb
* Product ID: 0x0622
* AAGUID: e1a9618350164f24b55be3ae23614cc6
