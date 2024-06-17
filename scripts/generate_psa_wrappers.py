#!/usr/bin/env python3
"""Generate wrapper functions for PSA function calls.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

### WARNING: the code in this file has not been extensively reviewed yet.
### We do not think it is harmful, but it may be below our normal standards
### for robustness and maintainability.

import argparse
from mbedtls_framework.code_wrapper import *

DEFAULT_C_OUTPUT_FILE_NAME = 'tests/src/psa_test_wrappers.c'
DEFAULT_H_OUTPUT_FILE_NAME = 'tests/include/test/psa_test_wrappers.h'

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=globals()['__doc__'])  #pylint: disable=invalid-name
    parser.add_argument('--log',
                        help='Stream to log to (default: no logging code)')
    parser.add_argument('--output-c',
                        metavar='FILENAME',
                        default=DEFAULT_C_OUTPUT_FILE_NAME,
                        help=('Output .c file path (default: {}; skip .c output if empty)'
                              .format(DEFAULT_C_OUTPUT_FILE_NAME)))
    parser.add_argument('--output-h',
                        metavar='FILENAME',
                        default=DEFAULT_H_OUTPUT_FILE_NAME,
                        help=('Output .h file path (default: {}; skip .h output if empty)'
                              .format(DEFAULT_H_OUTPUT_FILE_NAME)))
    options = parser.parse_args() #pylint: disable=invalid-name
    if options.log:
        generator = psa_test_wrapper.PSALoggingTestWrapper(DEFAULT_H_OUTPUT_FILE_NAME, #pylint: disable=invalid-name
                                          DEFAULT_C_OUTPUT_FILE_NAME,
                                          options.log) #type: PSATestWrapper
    else:
        generator = psa_test_wrapper.PSATestWrapper(DEFAULT_H_OUTPUT_FILE_NAME, #pylint: disable=invalid-name
                                   DEFAULT_C_OUTPUT_FILE_NAME)

    if options.output_h:
        generator.write_h_file(options.output_h)
    if options.output_c:
        generator.write_c_file(options.output_c)
