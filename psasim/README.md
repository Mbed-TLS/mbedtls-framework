# psasim

PSASIM holds necessary C source and header files which allows to test Mbed TLS in a "pure crypto client" scenario, i.e `MBEDTLS_PSA_CRYPTO_CLIENT && !MBEDTLS_PSA_CRYPTO_C`.
In practical terms it means that this allow to build PSASIM with Mbed TLS sources and get 2 Linux applications, a client and a server, which are connected through Linux's shared memeory, and in which the client relies on the server to perform all PSA Crypto operations.

The goal of PSASIM is _not_ to provide a ready-to-use solution for anyone looking to implement the pure crypto client structure (see [Limitations](#limitations) for details), but to provide an example of TF-PSA-Crypto RPC (Remote Procedure Call) implementation using Mbed TLS.
## Limitations

In the current implementation:

- Only Linux PC is supported.
- There can be only 1 client connected to 1 server.
- Shared memory is the only communication medium allowed. Others can be implemented (ex: net sockets), but in terms of simulation speed shared memory proved to be the fastest.
- Server is not secure at all: keys and operation structs are stored on the RAM, so they can easily be dumped.

## Testing

Please refer to `tests/scripts/components-psasim.sh` for guidance on how to build & test PSASIM:

- `component_test_psasim()`: builds the server and a couple of test clients which are used to evaluate some basic PSA Crypto API commands.
- `component_test_suite_with_psasim()`: builds the server and _all_ the usual test suites (those found under the `<mbedtls-root>/tests/suites/*` folder) which are used by the CI and runs them. A small subset of test suites (`test_suite_constant_time_hmac`,`test_suite_lmots`,`test_suite_lms`) are being skipped, for CI turnover time optimization. They can be run locally if required.
