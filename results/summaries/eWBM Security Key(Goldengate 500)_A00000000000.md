## eWBM Security Key(Goldengate 500)

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       70 |      76 |
| Client PIN  |       36 |      40 |
| FIDO 2.1    |        5 |       8 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests entries in the credential parameters list.
  * Falsely rejected cred params list with 1 good and 1 bad element.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_ALGORITHM`.
* Tests is user verification set to true is accepted in MakeCredential.
  * The user verification option (true) was not accepted.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_PIN_REQUIRED`.
* Tests if invalid UTF8 is caught in displayName.
  * UTF-8 correctness is not checked.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests is user verification set to true is accepted in GetAssertion.
  * The user verification option (true) was not accepted.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_PIN_REQUIRED`.
* Tests if new PIN requirement are enforced in SetPin.
  * Accepted a PIN with padding of length 32.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.
* Tests if new PIN requirement are enforced in ChangePin.
  * Accepted a PIN with padding of length 32.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.

### Device capabilities

* HID
  * CBOR: True
  * MSG : false
  * WINK: True
* Versions
  * U2F_V2
  * FIDO_2_0
  * FIDO_2_1_PRE
* Options
  * up
  * rk
  * uv
  * clientPin
  * credentialMgmtPreview
* Extensions
  * hmac-secret
  * credProtect
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: A00000000000
* Manufacturer: eWBM
* Vendor ID : 0x311f
* Product ID: 0x5c2f
* AAGUID: 361a308202784583a16f72a527f973e4
