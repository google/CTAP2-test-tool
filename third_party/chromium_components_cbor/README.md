# The chromium CBOR parser

*   Report a bug to: kaczmarczyck@google.com
*   Imported from https://chromium.googlesource.com/chromium/src/+/master/components/cbor/

A CBOR reader and writer in C++. For importing a new version, run the
import_converter.py on the new directory and check its outputs first. Check if
the diff on upstream and your CL match. All unit tests should still pass.

### Public:

*   `reader.h` : transform a std::vector<uint8_t> to a readable representation
*   `values.h` : the elements of CBOR codes, i.e. integers or maps
*   `writer.h` : transform a Value to a std::vector<uint8_t>
