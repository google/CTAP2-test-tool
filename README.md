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
using git.

### How to run

Running the tool without comments lists all avaiable devices. Select the device
you want to test by passing `--token_path`.

```shell
bazel run //:fido2_conformance
bazel run //:fido2_conformance -- --token_path=/dev/hidraw5
```

:warning: Please do not plug in other security keys with the same product ID, or
the tool might contact the wrong device during testing.

### Supported features

At the moment, we only support USB HID as a transport. We test the commands from
[CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.pdf),
but plan to add tests for supported extensions and
[CTAP 2.1](https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html).

### Results

While running the test tool, you will be prompted to touch or replug your
security key multiple times, to test various features. After finishing all
tests, you see a printed summary of your results in your terminal, and a report
file is created in the `results` directory.

### Contributing

If we didn't already test your security key or you have an updated version,
please create a pull request with your result file!

If you want to contribute code, please check
[Contributing.md](docs/contributing.md).

