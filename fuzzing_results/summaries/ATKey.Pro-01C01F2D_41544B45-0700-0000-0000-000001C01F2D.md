## ATKey.Pro-01C01F2D

| Category   |   Passed |   Total |
|------------|----------|---------|
| Fuzzing    |        1 |       3 |
| All        |        1 |       3 |

### Failed tests:

* Tests the corpus of CTAP GetAssertion commands.
  * Saved crash input to /home/fabian/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_GetAssertionParameters/542e4a656e0ca4779cbb642a0c79bbc1b1081e59. Ran a total of 687 files.
  * Received deprecated error code `0x13`
  * GetAuthToken failed.
  * GetKeyAgreement failed
  * In file 542e4a656e0ca4779cbb642a0c79bbc1b1081e59 GetAuthToken got error code - CTAP1_ERR_CHANNEL_BUSY
* Tests the corpus of CTAP ClientPIN commands.
  * Saved crash input to /home/fabian/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_ClientPinParameters/b1962064e7ed45dba5dc23ae37c752a130b78645. Ran a total of 3843 files.
  * GetAuthToken failed.
  * GetKeyAgreement failed
  * In file b1962064e7ed45dba5dc23ae37c752a130b78645 GetAuthToken got error code - CTAP1_ERR_OTHER

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
  * setMinPINLength
  * uv
  * clientPin
  * credMgmt
  * uvToken
  * bioEnroll
  * up
  * platConfig
  * rk
* Extensions
  * credBlob
  * hmac-secret
  * credProtect
* All counters were constant zero.

### Device information

* Serial number: 41544B45-0700-0000-0000-000001C01F2D
* Manufacturer: AuthenTrend Technology Inc.
* Vendor ID : 0x31bb
* Product ID: 0x0622
* AAGUID: e1a9618350164f24b55be3ae23614cc6
