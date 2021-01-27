## Nitrokey FIDO2 1.1.0

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       55 |      68 |
| Client PIN  |       31 |      34 |
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
* Tests if user touch is required for MakeCredential.
  * A credential was created without user presence.
  * Expected error code `CTAP2_ERR_USER_ACTION_TIMEOUT`, got `CTAP2_OK`.
* Tests if the user presence option is supported in GetAssertion.
  * The user presence option (false) was not accepted.
  * The failing error code is `CTAP2_ERR_NO_CREDENTIALS`.
* Tests if user verification set to false is accepted in GetAssertion.
  * The user verification option (false) was not accepted.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_NO_CREDENTIALS`.
* Tests if unknown options are ignored in GetAssertion.
  * Falsely rejected unknown option.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_LIMIT_EXCEEDED`.
* Tests if assertions with resident keys work.
  * GetAssertion failed for for resident key.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_NO_CREDENTIALS`.
* Tests if the PIN auth is correctly checked with a PIN set in GetAssertion.
  * Falsely rejected valid PIN auth.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_NO_CREDENTIALS`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if user touch is required for GetAssertion.
  * Cannot make credential for further tests.
  * The failing error code is `CTAP2_ERR_ACTION_TIMEOUT`.
* Tests whether credentials persist after replug.
  * A non-resident key did not persist after replug.
  * The failing error code is `CTAP2_ERR_ACTION_TIMEOUT`.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * FIDO_2_0
  * U2F_V2
* Options
  * rk
  * up
  * clientPin
* Extensions
  * hmac-secret
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: 20613388344B
* Manufacturer: Nitrokey
* Vendor ID : 0x20a0
* Product ID: 0x42b1
* AAGUID: 8876631bd4a0427f57730ec71c9e0279
