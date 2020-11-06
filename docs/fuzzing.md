# Fuzzing tool

The fuzzing tool aims at providing a general method to apply fuzzing to CTAP2
authenticators.

## Background

Fuzzing is the art of finding vulnerabilities with unexpected random inputs. 
It has been a very popular and effective testing technique throughout the
last years. Nevertheless, fuzzing external hardware is considered a difficult 
problem in the scientific community. Most classes of security vulnerabilities
are not observable, and even the crash behaviour varies from case to case. 
Furthermore, the goal to find a general approach for any authenticator rules 
out common solutions such as hardware emulation or binary instrumentation.

## Corpus testing

Our idea is fuzzing by proxy. We take [OpenSK](https://github.com/google/OpenSK)
(an open source implementation of a FIDO2 security key) as our fuzz target and 
generate interesting input data guided by OpenSK's code coverage. At the moment,
the fuzzing tool consists of running this input corpus on the device under test.
The corpus is hosted at a [git repository](https://github.com/mingxguo27/test_corpus)
and integrated as a submodule. You can also use your own data set for testing.

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
By default, our predefined data set is run with a blackbox monitor.

For more control, the following arguments are available:

- `--corpus_path`: The path to the corpus containing the test files.
- `--monitor`: The monitor type to be used. All supported optiones are:
    - `blackbox`: General blackbox monitor.
    - `gdb`: You can use it when your device enables GDB remote serial protocol.
    - `cortexm4_gdb`: You can use it when your device enables GDB remote serial
      protocol and runs on a ARM Cortex-M4 architecture.
- `--port`: If a GDB monitor is selected, the port to listen on for GDB remote 
  connection.
