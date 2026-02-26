#!/usr/bin/env python3
# Test suites code generator.
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""Dynamically generate test suite code.
"""

import argparse
import os
import sys

from mbedtls_framework import test_suite_preprocessor


def main():
    """
    Command line parser.

    :return:
    """
    parser = argparse.ArgumentParser(
        description=__doc__)

    parser.add_argument("-f", "--functions-file",
                        dest="funcs_file",
                        help="Functions file",
                        metavar="FUNCTIONS_FILE",
                        required=True)

    parser.add_argument("-d", "--data-file",
                        dest="data_file",
                        help="Data file",
                        metavar="DATA_FILE",
                        required=True)

    parser.add_argument("-t", "--template-file",
                        dest="template_file",
                        help="Template file",
                        metavar="TEMPLATE_FILE",
                        required=True)

    parser.add_argument("-s", "--suites-dir",
                        dest="suites_dir",
                        help="Suites dir",
                        metavar="SUITES_DIR",
                        required=True)

    parser.add_argument("--helpers-file",
                        dest="helpers_file",
                        help="Helpers file",
                        metavar="HELPERS_FILE",
                        required=True)

    parser.add_argument("-p", "--platform-file",
                        dest="platform_file",
                        help="Platform code file",
                        metavar="PLATFORM_FILE",
                        required=True)

    parser.add_argument("-o", "--out-dir",
                        dest="out_dir",
                        help="Dir where generated code and scripts are copied",
                        metavar="OUT_DIR",
                        required=True)

    args = parser.parse_args()

    data_file_name = os.path.basename(args.data_file)
    data_name = os.path.splitext(data_file_name)[0]

    out_c_file = os.path.join(args.out_dir, data_name + '.c')
    out_data_file = os.path.join(args.out_dir, data_name + '.datax')

    out_c_file_dir = os.path.dirname(out_c_file)
    out_data_file_dir = os.path.dirname(out_data_file)
    for directory in [out_c_file_dir, out_data_file_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)

    test_suite_preprocessor.generate_code(
        funcs_file=args.funcs_file,
        data_file=args.data_file,
        template_file=args.template_file,
        platform_file=args.platform_file,
        helpers_file=args.helpers_file,
        suites_dir=args.suites_dir,
        c_file=out_c_file,
        out_data_file=out_data_file)


if __name__ == "__main__":
    try:
        main()
    except test_suite_preprocessor.GeneratorInputError as err:
        sys.exit("%s: input error: %s" %
                 (os.path.basename(sys.argv[0]), str(err)))
