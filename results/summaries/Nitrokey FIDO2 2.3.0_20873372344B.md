## Nitrokey FIDO2 2.3.0

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       63 |      74 |
| Client PIN  |       36 |      40 |
| FIDO 2.1    |        5 |       8 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests entries in the credential parameters list.
  * Falsely rejected cred params list with 1 good and 1 bad element.
  * Expected error code `CTAP2_ERR_UNSUPPORTED_ALGORITHM`, got `CTAP2_ERR_INVALID_CBOR`.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_INVALID_CBOR`.
* Tests if unknown options are ignored in MakeCredential.
  * Falsely rejected unknown option.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_LIMIT_EXCEEDED`.
* Tests if client PIN fails with missing parameters in MakeCredential.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if invalid UTF8 is caught in displayName.
  * UTF-8 correctness is not checked.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests if the resident key option is rejected in GetAssertion.
  * The resident key option (false) was not rejected.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_OPTION`, got `CTAP2_OK`.
* Tests if unknown options are ignored in GetAssertion.
  * Falsely rejected unknown option.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_LIMIT_EXCEEDED`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if user touch is required for GetAssertion.
  * A credential was asserted without user presence.
  * Expected error code `CTAP2_ERR_USER_ACTION_TIMEOUT`, got `CTAP2_OK`.
* Tests if empty user IDs are omitted in the response.
  * The response includes user with an empty ID. This behaviour has known interoperability hurdles.
* Tests if new PIN requirement are enforced in SetPin.
  * Accepted a PIN with padding of length 128.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.
* Tests if new PIN requirement are enforced in ChangePin.
  * Accepted a PIN with padding of length 128.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * U2F_V2
  * FIDO_2_1_PRE
  * FIDO_2_0
* Options
  * up
  * rk
  * clientPin
  * credentialMgmtPreview
* Extensions
  * hmac-secret
  * credProtect
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: 20873372344B
* Manufacturer: Nitrokey
* Vendor ID : 0x20a0
* Product ID: 0x42b1
* AAGUID: c39efba6fcf44c3e828bfc4a6115a0ff
