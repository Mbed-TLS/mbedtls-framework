# Python scripts in Mbed TLS and TF-PSA-Crypto

TF-PSA-Crypto and Mbed TLS include Python code for building the libraries, for testing, and for maintenance. This document discusses how the various kinds of Python code are maintained.

## Categories of Python scripts

### User-invoked scripts

Several Python scripts are required to build Mbed TLS or TF-PSA-Crypto from the git source. Most of them are not directly user-facing, but invoked by the build system to generate various files (C files and test data files).

The following scripts are user-invoked:

* `scripts/config.py`
* Any script run by `make generated_files` or `framework/scripts/make_generated_files.py`.
* `tests/scripts/generate_test_code.py`

**Expected quality**: For scripts that generate library code unsupervised, we want a high level of confidence that the script's output will be correct. This is partly achieved through tests on the resulting code. These scripts should not break, but they normally run in controlled conditions (by the time users get the scripts, they and their inputs should have passed our CI). The scripts tend to change about as often as the corresponding library module might change.

**Portability**: These scripts must work on all Python versions that are documented in `README.md` in the applicable branch (or branches, for code in the framework). Typically this means any Python version that was officially supported when we last updated the readme. In an LTS branch, this means any Python version that was officially supported when the branch was created. Additionally, we try to minimize the necessary modules.

In Mbed TLS 3.6.x and TF-PSA-Crypto as of 1.0, there is one script that requires a third-party Python module, namely `scripts/generate_driver_wrappers.py`. It requires `Jinja2 >= 2.10.1` and `jsonschema >= 3.2.0`. We would like to get rid of this dependency and we are unlikely to accept any new dependency in user-invoked scripts.

### Test and maintenance scripts

This category includes all the Python code involved in running the CI, as well as scripts that maintainers might need to run from time to time.

The following scripts fall into this category, apart from user-invoked scripts:

* Any script invoked by `all.sh`, as well as `analyze_outcomes.py`.
* Possibly some scripts that maintainers use rarely, but that should keep working, such as `audit-validity-dates.py`.
* Several scripts in the `mbedtls-test` repository.

**Expected quality**: For test scripts, we want high confidence that we're getting the expected coverage. If the scripts break, the error trace should be comprehensible by a project maintainer or an external contributor. How often these scripts change is highly variable.

**Portability**: It's ok to require a reasonably recent Python version and extra packages. It's generally accepted that working on a project that uses Python scripts requires that project's virtual environment. All third-party package should be available from pypi.

As of January 2026, apart from `mbedtls-test` which is separate for historical reasons, all the test and maintenance scripts are subject to the same portability constraints because our tooling (CI python environment, pylint and mypy configuration) doesn't distinguish between them.

### Maintainer convenience scripts

This category covers scripts that are not necessary, but convenient. They are only potentially useful to project maintainers, possibly external contributors as well. They may provide IDE help, or project statistics, or help with the CI tooling.

Historically we had a few scripts in this category in the Mbed TLS repository. Nowadays they should go into https://github.com/Mbed-TLS/mbedtls-docs/tree/main/tools/bin (executable scripts only, but we could add a place for libraries if the need arises).

**Expected quality**: User beware. We just want the scripts to be not have major risks.

**Portability**: User beware.

## Python tooling

### CI environment

As of January 2026, for scripts invoked by `all.sh` (which includes all user-invoked scripts and most test scripts), the CI environment is some version of Python with the packages defined by `scripts/ci.requirements.txt`. The required packages are defined by the branch under test, but the Python version is the same for all branches. As of January 2026, the oldest Python on the CI is 3.6, even though the oldest branch (`mbedtls-3.6`) requests Python `>= 3.8`.

### Python validation

We run Pylint and mypy to validate all Python scripts and modules that `check-python-files.sh` can find: `scripts/*.py` and `tests/scripts/*.py` in each branch, as well as `scripts/*.py` and `scripts/mbedtls_framework/**.py` in the framework. Each branch has its own mypy and pylint configuration.

We apply the same validation standard to user-invoked scripts and test/maintainer scripts. This is partly historical and partly by design. We want a high level of quality for both kinds, so it makes sense to apply the same validation tools. However, it would make sense to use different Python versions, and that in turn could mean different versions of Pylint and mypy.

## Proposed changes

### Generated files: text vs crypto

#### Kinds of generator scripts

We can distinguish three kinds of scripts that generate C source or test data files, based on their inputs and on the kind of computation that they do. The examples are taken from TF-PSA-Crypto 1.0 and Mbed TLS 4.0.

* Text processors: these scripts parse part of the source code. They typically enumerate identifiers of a certain kind (macros, enums, functions, …) and generate C code or test data with lists or combinations of inputs. They mostly do some light data manipulation and text processing. They don't require any external libraries (except for `generate_driver_wrappers.py`).
  Examples: `generate_config_checks.py`, `generate_driver_wrappers.py`, `generate_psa_constants.py`, `generate_config_tests.py`, `generate_psa_tests.py`, `generate_errors.pl`, `generate_features.pl`, `generate_ssl_debug_helpers.py`, `generate_test_cert_macros.py`, `generate_query_config.pl` ,`generate_config_tests.py`.
  Also some scripts used for psasim that enumerate PSA functions.
* Text generators: these scripts are self-contained or have specific input files. They mostly do some light data manipulation and text processing. They don't require any libraries
  Examples: `generate_test_keys.py`, `generate_tls13_compat_tests.py`, `generate_tls_handshake_tests.py`, `generate_visualc_files.pl`.
* Crypto generators: these scripts perform some cryptographic calculations to generate test data. They have no or light dependencies on the source code (only to determine which subset of mechanisms the consuming branch supports). Currently, these scripts don't use any external libraries, however it would be useful to do so to support more cryptographic mechanisms.
  Examples: `generate_bignum_tests.py`, `generate_ecp_tests.py`.
  Also the part of `generate_psa_tests.py` that generates `test_suite_psa_crypto_low_hash.generated`.

#### Proposal: split out crypto generators

* Put crypto generator scripts in a new directory `framework/util` (name TBD). Arrange for these scripts to have access to `mbedtls_framework`, but not the other way round.
* Duplicate or parametrize `check-python-files.sh`. Run it in ancient Python for the existing scripts, and run the new instance with a recent Python and a larger set of packages.
* Commit the output of crypto generators as `test_suite_*.data` files.
* Have an `all.sh` job that checks that the output of crypto generators is up-to-date. This can be the same job that also runs `check-python-files` on the new directory, and that runs unit tests of new scripts where applicable.

The existing crypto generators are grandfathered in `framework/scripts` until we decide to move them. New generators that use some other Python package must go to the new directory.

### Separate user-invoked scripts from test and maintenance scripts

* Switch our default Python environment to the modern one (see [“Proposal: split out crypto generators”](#proposal-split-out-crypto-generators)).
* Have one `all.sh` component that tests user-invoked scripts (`make_generated_files.py` and `generate_test_code.py`, or do a build) in an old Python environment with few packages (`scripts/driver.requirements.txt`).
