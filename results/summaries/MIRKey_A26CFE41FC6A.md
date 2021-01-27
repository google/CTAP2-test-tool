## MIRKey

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       57 |      68 |
| Client PIN  |       30 |      34 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests nested CBOR in the exclude list of MakeCredential.
  * Maximum CBOR nesting depth exceeded with array in credential descriptor transport list item in make credential command for key 5.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests if the exclude list is used correctly.
  * MakeCredential failed for an unrelated relying party.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
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
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
* Tests if user touch is required for MakeCredential.
  * A credential was created without user presence.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * Expected error code `CTAP2_ERR_USER_ACTION_TIMEOUT`, got `CTAP2_OK`.
* Tests if the resident key option is rejected in GetAssertion.
  * The resident key option (false) was not rejected.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * Expected error code `CTAP2_ERR_INVALID_OPTION`, got `CTAP2_OK`.
* Tests if client PIN fails with missing parameters in GetAssertion.
  * Missing PIN protocol was not rejected when PIN is set.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
* Tests if user touch is required for GetAssertion.
  * A credential was asserted without user presence.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * Expected error code `CTAP2_ERR_USER_ACTION_TIMEOUT`, got `CTAP2_OK`.
* Tests if GetPinRetries works with missing parameters.
  * Missing key "1" for command client PIN command.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
* Tests if GetKeyAgreement works with missing parameters.
  * Missing key "1" for command client PIN command.
  * Expected error code `CTAP2_ERR_MISSING_PARAMETER`, got `CTAP2_OK`.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: false
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

* Serial number: A26CFE41FC6A
* Manufacturer: ellipticSecure
* Vendor ID : 0x0483
* Product ID: 0xa2ac
* AAGUID: eb3b131e59dc536ad176cb7306da10f5
