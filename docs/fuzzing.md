# Fuzzing

Fuzzing is the art of finding vulnerabilities with unexpected random inputs. 
It has been a very popular and effective testing technique throughout the
last years. Nevertheless, fuzzing external hardware is considered a difficult 
problem in the scientific community. In our test tool, we provide a proof-of-
concept fuzzing approach for authenticators.

## Corpus testing

Our idea is fuzzing by proxy. We take [OpenSK](https://github.com/google/OpenSK)
(an open source implementation of a FIDO2 security key) as our fuzz target and 
generate interesting input data guided by OpenSK's code coverage. At the moment,
the fuzzing tool consists of running this input corpus on the authenticator under
test. You can also use your own data set for testing.

## Device monitoring

Apart from a general blackbox solution, we provide a more detailed crash report
for a device enabling GDB remote serial protocol via JTAG/SWD, assuming that a 
breakpoint is triggered upon kernel panic. Currently only the ARM Cortex-M4 
processor is supported.

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