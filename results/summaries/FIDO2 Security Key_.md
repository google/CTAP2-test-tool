## FIDO2 Security Key

| Category    |   Passed |   Total |
|-------------|----------|---------|
| All         |       67 |      68 |
| Client PIN  |       34 |      34 |
| HMAC Secret |        1 |       1 |

### Failed tests:

* Tests if empty user IDs are omitted in the response.
  * Cannot make credential with an empty user ID.
  * A prompt was expected, but not performed. Sometimes it is just not recognized if performed too fast.
  * The failing error code is `CTAP2_ERR_INVALID_CBOR`.

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
* All counters were strictly incremented by 1.

### Device information

* Serial number: None
* Manufacturer: TOKEN2
* Vendor ID : 0x1ea8
* Product ID: 0xfc25
* AAGUID: ab32f0c62239afbbc470d2ef4e254db7
