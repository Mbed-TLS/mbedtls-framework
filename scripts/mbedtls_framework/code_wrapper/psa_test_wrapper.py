#!/usr/bin/env python3
"""Generate wrapper functions for PSA function calls.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

### WARNING: the code in this file has not been extensively reviewed yet.
### We do not think it is harmful, but it may be below our normal standards
### for robustness and maintainability.

import argparse
import itertools
import os
from typing import Iterator, List, Collection, Optional, Tuple

from mbedtls_framework import build_tree
from mbedtls_framework import c_parsing_helper
from mbedtls_framework import c_wrapper_generator
from mbedtls_framework import typing_util

from psa_buffer import BufferParameter
from psa_wrapper import PSAWrapper, PSALoggingWrapper, DEFAULTS

class PSATestWrapper(PSAWrapper):
    """Generate a C source file containing wrapper functions for PSA Crypto API calls."""

    _CPP_GUARDS = ('defined(MBEDTLS_PSA_CRYPTO_C) && ' +
                   'defined(MBEDTLS_TEST_HOOKS) && \\\n    ' +
                   '!defined(RECORD_PSA_STATUS_COVERAGE_LOG)')
    _WRAPPER_NAME_PREFIX = 'mbedtls_test_wrap_'
    _WRAPPER_NAME_SUFFIX = ''

    __PROLOGUE__ = """
        #if {}

        #include <psa/crypto.h>

        #include <test/memory.h>
        #include <test/psa_crypto_helpers.h>
        #include <test/psa_test_wrappers.h>
        """


class PSALoggingTestWrapper(PSATestWrapper, PSALoggingWrapper):
    """Generate a C source file containing wrapper functions that log PSA Crypto API calls."""

    def __init__(self, output_h_f: str,
                       output_c_f: str,
                       stream: str,
                       in_headers:  Collection[str] = DEFAULTS["input_headers"]) -> None:
        super().__init__(output_h_f, output_c_f, in_headers)# type: ignore[arg-type]
        self.set_stream(stream)

