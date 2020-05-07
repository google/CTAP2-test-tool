# Test Suite for FIDO2

The test suite intents to make it easier for developers to find bugs in their
CTAP2 implementation.

Disclaimer: Those tests reflect the author's interpretation of the
specification. It is not to be confused with certification by the FIDO Alliance.
Please check the [FIDO Alliance web page](https://fidoalliance.org/) for more
information.

## How to install

The build system is bazel. Please make sure you have all dependencies installed.
Example command:

```shell
apt-get install bazel libudev-dev libusb-1.0-0-dev libfox-1.6-dev \
    autotools-dev autoconf automake libtool
```

For your first run, the build system will fetch all other necessary libraries
using git.

## How to run

```shell
bazel run //:fido2_conformance
bazel run //:fido2_conformance -- --token_path=/dev/hidraw5
```

