#!/usr/bin/env python3

# make_generated_files.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""
Generate the TF-PSA-Crypto generated files
"""
import argparse
import subprocess
import sys

from pathlib import Path
from typing import List, Optional

from mbedtls_framework import build_tree

class GenerationScript:
    """
    Representation of a script generating a configuration independent file.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, script: Path, files: List[Path]):
        """ Path from the root of Mbed TLS or TF-PSA-Crypto of the generation script """
        self.script = script
        """
        List of the default paths from the Mbed TLS or TF-PSA-Crypto root of the
        files the script generates.
        """
        self.files = files

def get_generation_script_files(generation_script: str):
    """
    Get the list of the default paths of the files that a given script
    generates. It is assumed that the script supports the "--list" option.
    """
    files = []
    output = subprocess.check_output([generation_script, "--list"],
                                     universal_newlines=True)
    for line in output.splitlines():
        files.append(Path(line))

    return files

if build_tree.looks_like_tf_psa_crypto_root("."):
    TF_PSA_CRYPTO_GENERATION_SCRIPTS = [
        GenerationScript(
            Path("scripts/generate_driver_wrappers.py"),
            [Path("core/psa_crypto_driver_wrappers.h"),
             Path("core/psa_crypto_driver_wrappers_no_static.c")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_test_keys.py"),
            [Path("tests/include/test/test_keys.h")],
        ),
        GenerationScript(
            Path("scripts/generate_psa_constants.py"),
            [Path("programs/psa/psa_constant_names_generated.c")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_bignum_tests.py"),
            get_generation_script_files("framework/scripts/generate_bignum_tests.py"),
        ),
        GenerationScript(
            Path("framework/scripts/generate_config_tests.py"),
            get_generation_script_files("framework/scripts/generate_config_tests.py"),
        ),
        GenerationScript(
            Path("framework/scripts/generate_ecp_tests.py"),
            get_generation_script_files("framework/scripts/generate_ecp_tests.py"),
        ),
        GenerationScript(
            Path("framework/scripts/generate_psa_tests.py"),
            get_generation_script_files("framework/scripts/generate_psa_tests.py"),
        ),
    ]


if build_tree.looks_like_mbedtls_root(".") and not build_tree.is_mbedtls_3_6():
    MBEDTLS_GENERATION_SCRIPTS = [
        GenerationScript(
            Path("scripts/generate_errors.pl"),
            [Path("library/error.c")],
        ),
        GenerationScript(
            Path("scripts/generate_features.pl"),
            [Path("library/version_features.c")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_ssl_debug_helpers.py"),
            [Path("library/ssl_debug_helpers_generated.c")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_test_keys.py"),
            [Path("tests/include/test/test_keys.h")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_test_cert_macros.py"),
            [Path("tests/include/test/test_certs.h")],
        ),
        GenerationScript(
            Path("scripts/generate_query_config.pl"),
            [Path("programs/test/query_config.c")],
        ),
        GenerationScript(
            Path("framework/scripts/generate_config_tests.py"),
            get_generation_script_files("framework/scripts/generate_config_tests.py"),
        ),
        GenerationScript(
            Path("framework/scripts/generate_tls13_compat_tests.py"),
            [Path("tests/opt-testcases/tls13-compat.sh")],
        ),
        GenerationScript(
            Path("scripts/generate_visualc_files.pl"),
            get_generation_script_files("scripts/generate_visualc_files.pl"),
        ),
    ]

def get_generated_files(generation_scripts: List[GenerationScript]):
    """
    List the generated files in Mbed TLS or TF-PSA-Crypto. The path from root
    is returned for each generated files.
    """
    files = []
    for generation_script in generation_scripts:
        files += generation_script.files

    return files

def make_generated_files(generation_scripts: List[GenerationScript]):
    """
    Generate the configuration independent files in their default location in
    the Mbed TLS or TF-PSA-Crypto tree.
    """
    for generation_script in generation_scripts:
        subprocess.run([str(generation_script.script)], check=True)

def main():
    """
    Main function of this program
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--list', action='store_true',
                        default=False, help='List generated files.')

    args = parser.parse_args()

    if not build_tree.looks_like_root("."):
        raise RuntimeError("This script must be run from Mbed TLS or TF-PSA-Crypto root.")

    if build_tree.looks_like_tf_psa_crypto_root("."):
        generation_scripts = TF_PSA_CRYPTO_GENERATION_SCRIPTS
    elif not build_tree.is_mbedtls_3_6():
        generation_scripts = MBEDTLS_GENERATION_SCRIPTS
    else:
        raise Exception("No support for Mbed TLS 3.6")

    if args.list:
        files = get_generated_files(generation_scripts)
        for file in files:
            print(str(file))
    else:
        make_generated_files(generation_scripts)

if __name__ == "__main__":
    sys.exit(main())
