## eWBM Security Key(Goldengate 500)

| Category   |   Passed |   Total |
|------------|----------|---------|
| Fuzzing    |        0 |       3 |
| All        |        0 |       3 |

### Failed tests:

* Tests the corpus of CTAP MakeCredential commands.
  * Saved crash input to /run/media/fabian/enc/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_MakeCredentialParameters/3f9405466d8fdf2bcfdfa84190877f2259f62af3. Ran a total of 8066 files.
  * A prompt was sent unexpectedly.
  * GetAuthToken failed.
  * GetKeyAgreement failed
  * In file 3f9405466d8fdf2bcfdfa84190877f2259f62af3 GetAuthToken got error code - CTAP1_ERR_TIMEOUT
* Tests the corpus of CTAP GetAssertion commands.
  * Saved crash input to /run/media/fabian/enc/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_GetAssertionParameters/81fe7bd742c154c37cd69f559a7fa2e982d85104. Ran a total of 855 files.
  * A prompt was sent unexpectedly.
  * GetAuthToken failed.
  * GetKeyAgreement failed
  * In file 81fe7bd742c154c37cd69f559a7fa2e982d85104 GetAuthToken got error code - CTAP1_ERR_TIMEOUT
* Tests the corpus of CTAP ClientPIN commands.
  * Saved crash input to /run/media/fabian/enc/Projekte/CTAP2-test-tool/corpus_tests/artifacts/Cbor_ClientPinParameters/652a2941edfb5da20e4cc5969521c8a229d12eaa. Ran a total of 1748 files.
  * GetAuthToken failed.
  * In file 56394cb7d723181ed63f761fc99c9c94751308e3 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 6a45b8d00467ca5bfc90d4d6548034bcc7eae3be GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file c10d2dd44d1e862a5891517bd99b0f074d137117 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 5b570b7e5e4736b4a70bc7145f67258c4f3e5e3c GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file c1e4a64f396d18e582bfc31a3b2d778c84a830f3 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 843e768a2ee3e64865f80da2bbcc03eee865247b GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file a210d75b2d42f9c4357546a7e28a63a3ab5a7890 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 4c1a2f9655b2fd2ddf9b74341cad7746de904e30 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 4c6483e2f917dd9971e76f015ae2aede032a5a56 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 6776fced0481d2e209cba5ed4a835a557adbc304 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 2cddede03e0d88ce64d0b84ffcd8e6b4be9a4a57 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file bf598a5223392160e9f966ea16968df48afdd2e7 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file c01d8781780f26da5f40b1f0d59b1dd113584685 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 38a2344ca4776a8043b515b3929b7ad3dd424620 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 66e05b7d8cbcf57d83f68cde9906399cf8e77b79 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 7649ff784dc65f47c922381771934fe4d9251dd9 GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 3aff0a92e3606180ce5f5c703346a067b0ebaa9e GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file 50dd9f7300b871979fb1b9f56ee91dc0cb11e7ee GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file b0a025f71e17beddcf74e97cda41170ec8ba6cff GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * In file e788f31f2fc19492492dc8a29e0c12a8253428cc GetAuthToken got error code - CTAP2_ERR_PIN_INVALID
  * GetKeyAgreement failed
  * In file 652a2941edfb5da20e4cc5969521c8a229d12eaa GetAuthToken got error code - CTAP1_ERR_TIMEOUT

### Device capabilities

* HID
  * CBOR: True
  * MSG : false
  * WINK: True
* Versions
  * U2F_V2
  * FIDO_2_1_PRE
  * FIDO_2_0
* Options
  * rk
  * up
  * clientPin
  * uv
  * credentialMgmtPreview
* Extensions
  * credProtect
  * hmac-secret
* All counters were constant zero.

### Device information

* Serial number: A00000000000
* Manufacturer: eWBM
* Vendor ID : 0x311f
* Product ID: 0x5c2f
* AAGUID: 361a308202784583a16f72a527f973e4
