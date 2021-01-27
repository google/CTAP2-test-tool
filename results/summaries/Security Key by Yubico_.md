## Security Key by Yubico

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       58 |      67 |
| Client PIN  |       31 |      33 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests if MakeCredential works with missing parameters.
  * Missing key "3" for command make credential command.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests bad parameters in user parameter of MakeCredential.
  * Optional entry icon not recognized.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_MISSING_PARAMETER`.
* Tests nested CBOR in the exclude list of MakeCredential.
  * Maximum CBOR nesting depth exceeded with array in credential descriptor transport list item in make credential command for key 5.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests if the resident key option is rejected in GetAssertion.
  * The resident key option (false) was not rejected.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_OPTION`, got `CTAP2_OK`.
* Tests if empty user IDs are omitted in the response.
  * Cannot make credential with an empty user ID.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP1_ERR_INVALID_PARAMETER`.
* Tests if PIN requirement are enforced in SetPin.
  * Accepted a PIN with length > 63.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.
* Tests if PIN requirement are enforced in ChangePin.
  * Accepted a PIN with length > 63.
  * Expected error code `CTAP2_ERR_PIN_POLICY_VIOLATION`, got `CTAP2_OK`.
* Tests if the Wink response matches the capability bit.
  * The reported WINK capability did not match the observed response.
* Tests if Reset actually deletes credentials.
  * Cannot make credential for further tests.
  * The failing error code is `CTAP1_ERR_OTHER`.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * U2F_V2
  * FIDO_2_0
* Options
  * rk
  * up
  * clientPin
* Extensions
  * hmac-secret
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: None
* Manufacturer: Yubico
* Vendor ID : 0x1050
* Product ID: 0x0120
* AAGUID: f8a011f38c0a4d15800617111f9edc7d
