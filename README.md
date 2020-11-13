# <img alt="Test Tool logo" src="docs/img/logo.svg" width="200px">

## CTAP2 test tool

The test suite intents to make it easier for developers to find bugs in their
CTAP2 implementation.

### Disclaimer
Those tests reflect the author's interpretation of the specification. It is not
to be confused with certification by the FIDO Alliance. Please check the
[FIDO Alliance web page](https://fidoalliance.org/) for more information.

### How to install

The build system is bazel. Please make sure you have all dependencies installed.
Example command for Ubuntu:

```shell
apt-get install bazel libudev-dev autotools-dev autoconf automake libtool
```

On your first run, the build system will fetch all other necessary libraries
using git. The tool is tested on Linux and MacOS with GCC 9 and higher.

### How to run

:warning: This tool will irreversibly delete all credentials on your device.

Running the tool without comments lists all avaiable devices. Select the device
you want to test by passing `--token_path`. For Unix, if only one CTAP2
compatible device is plugged in, you can simply run:

```shell
./run.sh
```

For more control, try i.e.:

```shell
bazel run //:fido2_conformance
bazel run //:fido2_conformance -- --token_path=/dev/hidraw0
```

:warning: Please do not plug in other security keys with the same product ID, or
the tool might contact the wrong device during testing.

While running the test tool, you will be prompted to touch or replug your
security key multiple times, to test various features.

### Supported features

At the moment, we only support USB HID as a transport. We test the commands from
[CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.pdf),
but plan to add tests for supported extensions and
[CTAP 2.1](https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html).
The security key must support resident keys and user presence. Also, security
keys with displays are untested so far.

#### Fuzzing
In addition to the CTAP2 specification conformance test, we provide a proof-of-concept
fuzzing tool. Please check [fuzzing.md](docs/fuzzing.md) for a detailed guide.

### Results

For more information on checking or contributing test results, please check
[results.md](docs/results.md).

### Contributing

If we didn't already test your security key or you have an updated version,
please create a pull request with your result file!

If you want to contribute code, please check
[contributing.md](docs/contributing.md).

