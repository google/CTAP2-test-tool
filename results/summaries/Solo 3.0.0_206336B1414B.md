## Solo 3.0.0

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       61 |      68 |
| Client PIN  |       32 |      34 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests nested CBOR in the exclude list of MakeCredential.
  * Maximum CBOR nesting depth exceeded with array in credential descriptor transport list item in make credential command for key 5.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests entries in the credential parameters list.
  * Falsely rejected cred params list with 1 good and 1 bad element.
  * Received deprecated error code `0x10`
  * Expected error code `CTAP2_ERR_UNSUPPORTED_ALGORITHM`, got `CTAP1_ERR_OTHER`.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP1_ERR_OTHER`.
* Tests if unknown options are ignored in MakeCredential.
  * Falsely rejected unknown option.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_LIMIT_EXCEEDED`.
* Tests if client PIN fails with missing parameters in MakeCredential.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if unknown options are ignored in GetAssertion.
  * Falsely rejected unknown option.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_LIMIT_EXCEEDED`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if empty user IDs are omitted in the response.
  * The response includes user with an empty ID. This behaviour has known interoperability hurdles.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * FIDO_2_0
  * U2F_V2
* Options
  * clientPin
  * rk
  * up
* Extensions
  * hmac-secret
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: 206336B1414B
* Manufacturer: SoloKeys
* Vendor ID : 0x0483
* Product ID: 0xa2ca
* AAGUID: 8876631bd4a0427f57730ec71c9e0279
