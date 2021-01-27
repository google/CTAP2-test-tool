## BioPassFIDO2

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       67 |      76 |
| Client PIN  |       36 |      40 |
| FIDO 2.1    |        7 |       8 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests if unknown extensions are ignored in MakeCredential.
  * Failure to accept a valid extension.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_OPTION`.
* Tests if the exclude list is used correctly.
  * MakeCredential failed for an unrelated relying party.
  * The failing error code is `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
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
* Tests if invalid UTF8 is caught in displayName.
  * UTF-8 correctness is not checked.
  * A prompt was sent unexpectedly.
  * Expected error code `CTAP2_ERR_INVALID_CBOR`, got `CTAP2_OK`.
* Tests if unknown extensions are ignored in GetAssertion.
  * Failure to accept a valid extension.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_UNSUPPORTED_OPTION`.
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
  * U2F_V2
  * FIDO_2_1_PRE
  * FIDO_2_0
* Options
  * clientPin
  * rk
  * up
  * credentialMgmtPreview
  * uv
* Extensions
  * hmac-secret
  * credProtect
* All counters were strictly increasing, but not necessarily incremented by 1.

### Device information

* Serial number: None
* Manufacturer: FS
* Vendor ID : 0x096e
* Product ID: 0x085d
* AAGUID: 77010bd7212a4fc9b236d2ca5e9d4084
