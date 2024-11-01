"""Library for constructing an Mbed TLS test case.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import binascii
import os
import sys
from typing import Iterable, List, Optional

from . import build_tree
from . import psa_information
from . import typing_util

HASHES_3_6 = {
    "PSA_ALG_MD5" : "MBEDTLS_MD_CAN_MD5",
    "PSA_ALG_RIPEMD160" : "MBEDTLS_MD_CAN_RIPEMD160",
    "PSA_ALG_SHA_1" : "MBEDTLS_MD_CAN_SHA1",
    "PSA_ALG_SHA_224" : "MBEDTLS_MD_CAN_SHA224",
    "PSA_ALG_SHA_256" : "MBEDTLS_MD_CAN_SHA256",
    "PSA_ALG_SHA_384" : "MBEDTLS_MD_CAN_SHA384",
    "PSA_ALG_SHA_512" : "MBEDTLS_MD_CAN_SHA512",
    "PSA_ALG_SHA3_224" : "MBEDTLS_MD_CAN_SHA3_224",
    "PSA_ALG_SHA3_256" : "MBEDTLS_MD_CAN_SHA3_256",
    "PSA_ALG_SHA3_384" : "MBEDTLS_MD_CAN_SHA3_384",
    "PSA_ALG_SHA3_512" : "MBEDTLS_MD_CAN_SHA3_512"
}

PK_MACROS_3_6 = {
    "PSA_KEY_TYPE_ECC_PUBLIC_KEY" : "MBEDTLS_PK_HAVE_ECC_KEYS"
}

def hex_string(data: bytes) -> str:
    return '"' + binascii.hexlify(data).decode('ascii') + '"'

class MissingDescription(Exception):
    pass

class MissingFunction(Exception):
    pass

class TestCase:
    """An Mbed TLS test case."""

    def __init__(self, description: Optional[str] = None):
        self.comments = [] #type: List[str]
        self.description = description #type: Optional[str]
        self.dependencies = [] #type: List[str]
        self.function = None #type: Optional[str]
        self.arguments = [] #type: List[str]

    def add_comment(self, *lines: str) -> None:
        self.comments += lines

    def set_description(self, description: str) -> None:
        self.description = description

    def set_dependencies(self, dependencies: List[str]) -> None:
        self.dependencies = dependencies

    def set_function(self, function: str) -> None:
        self.function = function

    def set_arguments(self, arguments: List[str]) -> None:
        self.arguments = arguments

    def check_completeness(self) -> None:
        if self.description is None:
            raise MissingDescription
        if self.function is None:
            raise MissingFunction

    def write(self, out: typing_util.Writable) -> None:
        """Write the .data file paragraph for this test case.

        The output starts and ends with a single newline character. If the
        surrounding code writes lines (consisting of non-newline characters
        and a final newline), you will end up with a blank line before, but
        not after the test case.
        """
        self.check_completeness()
        assert self.description is not None # guide mypy
        assert self.function is not None # guide mypy
        out.write('\n')
        for line in self.comments:
            out.write('# ' + line + '\n')
        out.write(self.description + '\n')
        if self.dependencies:
            out.write('depends_on:' + ':'.join(self.dependencies) + '\n')
        out.write(self.function + ':' + ':'.join(self.arguments) + '\n')

def write_data_file(filename: str,
                    test_cases: Iterable[TestCase],
                    caller: Optional[str] = None) -> None:
    """Write the test cases to the specified file.

    If the file already exists, it is overwritten.
    """
    if caller is None:
        caller = os.path.basename(sys.argv[0])
    tempfile = filename + '.new'
    with open(tempfile, 'w') as out:
        out.write('# Automatically generated by {}. Do not edit!\n'
                  .format(caller))
        for tc in test_cases:
            tc.write(out)
        out.write('\n# End of automatically generated file.\n')
    os.replace(tempfile, filename)

def psa_or_3_6_feature_macro(psa_alg: str,
                             domain_3_6: str) -> str:
    """Determine the dependency symbol for a given psa_alg based on
       the domain and Mbed TLS version. For more information about the domains,
       and MBEDTLS_MD_CAN_ prefixed symbols, see transition-guards.md.
    """

    if domain_3_6 == "DOMAIN_3_6_PSA" or not build_tree.is_mbedtls_3_6():
        if psa_alg in PK_MACROS_3_6 or psa_alg in HASHES_3_6:
            return psa_alg
        if psa_alg.startswith('PSA_ALG_') and \
            psa_alg[8:] in ['MD5', 'RIPEMD160', 'SHA_1', 'SHA_224', 'SHA_256',
                            'SHA_384', 'SHA_512', 'SHA3_224',
                            'SHA3_256', 'SHA3_384', 'SHA3_512']:
            return psa_information.psa_want_symbol(psa_alg)

    if psa_alg in HASHES_3_6:
        return HASHES_3_6[psa_alg]
    if psa_information.psa_want_symbol(psa_alg) in HASHES_3_6:
        return HASHES_3_6[psa_information.psa_want_symbol(psa_alg)]
    if psa_alg in PK_MACROS_3_6:
        return PK_MACROS_3_6[psa_alg]

    raise ValueError('Unable to determine dependency symbol for ' + psa_alg)
