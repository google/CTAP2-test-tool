## HyperFIDO

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       62 |      68 |
| Client PIN  |       30 |      34 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests entries in the credential parameters list.
  * Falsely rejected cred params list with 1 good and 1 bad element.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_ALGORITHM`.
* Tests is user verification set to true is accepted in MakeCredential.
  * The user verification option (true) was not accepted.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_OPTION`.
* Tests if client PIN fails with missing parameters in MakeCredential.
  * Missing PIN protocol was not rejected when PIN is set.
  * Expected error code `CTAP2_ERR_PIN_REQUIRED`, got `CTAP2_ERR_MISSING_PARAMETER`.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests credential descriptors in the allow list of GetAssertion.
  * Failure to accept a valid credential descriptor.
  * The failing error code is `CTAP2_ERR_NO_CREDENTIALS`.
* Tests is user verification set to true is accepted in GetAssertion.
  * The user verification option (true) was not accepted.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_OPTION`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * GetAssertion failed with PIN protocol, but without a token when PIN is set.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_MISSING_PARAMETER`.

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
  * uv
* Extensions
  * hmac-secret
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: None
* Manufacturer: HS
* Vendor ID : 0x2ccf
* Product ID: 0x0854
* AAGUID: 9f77e279a6e24d58b70031e5943c6a98
