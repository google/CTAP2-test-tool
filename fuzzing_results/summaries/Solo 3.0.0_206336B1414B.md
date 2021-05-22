## Solo 3.0.0

| Category   |   Passed |   Total |
|------------|----------|---------|
| Fuzzing    |        2 |       3 |
| All        |        2 |       3 |

### Failed tests:

* Tests the corpus of CTAP ClientPIN commands.
  * Saved crash input to /run/media/fabian/enc/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_ClientPinParameters/6552d1c13cf46f864058c26f06ee615d9226fd87. Ran a total of 525 files.
  * Received deprecated error code `0x10`
  * Received deprecated error code `0x13`
  * GetAuthToken failed.
  * GetKeyAgreement failed
  * In file 6552d1c13cf46f864058c26f06ee615d9226fd87 GetAuthToken got error code - CTAP1_ERR_TIMEOUT

### Device capabilities

* HID
  * CBOR: True
  * MSG : True
  * WINK: True
* Versions
  * FIDO_2_0
  * U2F_V2
* Options
  * up
  * clientPin
  * rk
* Extensions
  * hmac-secret
* All counters were constant zero.

### Device information

* Serial number: 206336B1414B
* Manufacturer: SoloKeys
* Vendor ID : 0x0483
* Product ID: 0xa2ca
* AAGUID: 8876631bd4a0427f57730ec71c9e0279
