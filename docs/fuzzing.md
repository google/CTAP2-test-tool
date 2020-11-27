# Fuzzing tool

The fuzzing tool provides a general method to apply fuzzing to CTAP2
authenticators.

## Background

Fuzzing is the art of finding vulnerabilities with unexpected random inputs.
It has been a very popular and effective testing technique throughout the
last years. Nevertheless, fuzzing external hardware is considered a difficult
problem in the scientific and security community. Most classes of security
vulnerabilities are not observable, and even the crash behaviour varies from case
to case. Furthermore, the goal to find a general approach for any authenticator
rules out common solutions such as hardware emulation or binary instrumentation.

## How does it work

Our idea is fuzzing by proxy. We take [OpenSK](https://github.com/google/OpenSK)
(an open source implementation of a FIDO2 security key) as our fuzz target and
generate interesting input data guided by OpenSK's code coverage. At the moment,
we support two fuzzing modes:
1. Run this input corpus directly on the device under test.
2. Fuzz the device under test using this input corpus as a basis for mutation.
The corpus is hosted at a [git repository](https://github.com/google/CTAP2-test-tool-corpus)
and integrated as a submodule, which will be downloaded upon cloning the test
tool repository. When downloading the test tool manually, you can copy the corpus
to `corpus_tests/test_corpus/`. You can also change this path and use your own
data set for testing via program arguments as explained below.

## Device monitoring

In our general blackbox solution, we make use of the `ClientPin` command to
detect a crash on the device. It allows identifying both hang and reboot-after-
crash behaviour by attempting to retrieve and compare the current `pinToken`.
Apart from that, we provide a more detailed crash report for a device enabling
GDB remote serial protocol via JTAG/SWD, assuming that a breakpoint is triggered
upon kernel panic. Currently only the ARM Cortex-M4 processor is supported.

## How to run

As the main test tool, you can select the device you want to test by passing
`--token_path`. For Unix, if only one CTAP2 compatible device is plugged in,
you can simply run:
```shell
./run_fuzzing.sh
```
By default, our predefined data set is run on the device with a blackbox monitor.

For more control, the following arguments are available:

- `--run_mode`: `corpus_test` runs the given corpus and `fuzzing` starts mutation-
  based fuzzing.
- `--corpus_path`: The path to the corpus containing the test files.
- `--monitor`: The monitor type to be used. All supported options are:
    - `blackbox`: General blackbox monitor.
    - `gdb`: You can use it when your device enables GDB remote serial protocol.
    - `cortexm4_gdb`: You can use it when your device enables GDB remote serial
      protocol and runs on an ARM Cortex-M4 architecture.
- `--port`: If a GDB monitor is selected, the port to listen on for GDB remote
  connection.

In the fuzzing mode using mutations to run indefinitely, more options are
supported:

- `--fuzzing_mode`: The type of inputs to be fuzzed. All supported options are:
    - `cbor_make_credential`
    - `cbor_get_assertion`
    - `cbor_client_pin`
    - `ctaphid_raw`
- `--num_runs`: Number of inputs to be run. By default, the fuzzer will run
  indefinitely.
- `--max_length`: Maximum length of an input. By default, there is no limit.
- `--max_mutation_degree`: Maximum number of successive mutation operations to be
  applied. By default, the degree is 10.

## How to reproduce

The files causing a reported crash are saved to `corpus_tests/artifacts/` by
default. You can run the fuzzing test again providing this corpus path to
reproduce the crash.
```shell
./run_fuzzing.sh --corpus_path=corpus_tests/artifacts/
```

