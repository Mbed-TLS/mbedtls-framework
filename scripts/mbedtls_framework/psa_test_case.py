"""Generate test cases for PSA API calls, with automatic dependencies.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import os
import re
from typing import FrozenSet, List, Optional, Set

from . import psa_information
from . import test_case


# A temporary hack: at the time of writing, not all dependency symbols
# are implemented yet. Skip test cases for which the dependency symbols are
# not available. Once all dependency symbols are available, this hack must
# be removed so that a bug in the dependency symbols properly leads to a test
# failure.
def read_implemented_dependencies(acc: Set[str], filename: str) -> None:
    with open(filename) as input_stream:
        for line in input_stream:
            for symbol in re.findall(r'\bPSA_WANT_\w+\b', line):
                acc.add(symbol)

_implemented_dependencies = None #type: Optional[FrozenSet[str]] #pylint: disable=invalid-name

def find_dependencies_not_implemented(dependencies: List[str]) -> List[str]:
    """List the dependencies that are not implemented."""
    global _implemented_dependencies #pylint: disable=global-statement,invalid-name
    if _implemented_dependencies is None:
        # Temporary, while Mbed TLS does not just rely on the TF-PSA-Crypto
        # build system to build its crypto library. When it does, the first
        # case can just be removed.
        if os.path.isdir('tf-psa-crypto'):
            include_dir = 'tf-psa-crypto/include'
        else:
            include_dir = 'include'
        acc = set() #type: Set[str]
        for filename in [
                os.path.join(include_dir, 'psa/crypto_config.h'),
                os.path.join(include_dir, 'psa/crypto_adjust_config_synonyms.h'),
        ]:
            read_implemented_dependencies(acc, filename)
        _implemented_dependencies = frozenset(acc)
    return [dep
            for dep in dependencies
            if (dep.lstrip('!') not in _implemented_dependencies and
                dep.lstrip('!').startswith('PSA_WANT'))]


class TestCase(test_case.TestCase):
    """A PSA test case with automatically inferred dependencies.

    For mechanisms like ECC curves where the support status includes
    the key bit-size, this class assumes that only one bit-size is
    involved in a given test case.
    """

    def __init__(self, dependency_prefix: Optional[str] = None) -> None:
        """Construct a test case for a PSA Crypto API call.

        `dependency_prefix`: prefix to use in dependencies. Defaults to
                             ``'PSA_WANT_'``. Use ``'MBEDTLS_PSA_BUILTIN_'``
                             when specifically testing builtin implementations.
        """
        super().__init__()
        del self.dependencies
        self.manual_dependencies = [] #type: List[str]
        self.automatic_dependencies = set() #type: Set[str]
        self.dependency_prefix = dependency_prefix #type: Optional[str]
        self.key_bits = None #type: Optional[int]
        self.key_pair_usage = None #type: Optional[str]

    def set_key_bits(self, key_bits: Optional[int]) -> None:
        """Use the given key size for automatic dependency generation.

        Call this function before set_arguments() if relevant.

        This is only relevant for ECC and DH keys. For other key types,
        this information is ignored.
        """
        self.key_bits = key_bits

    def set_key_pair_usage(self, key_pair_usage: Optional[str]) -> None:
        """Use the given suffix for key pair dependencies.

        Call this function before set_arguments() if relevant.

        This is only relevant for key pair types. For other key types,
        this information is ignored.
        """
        self.key_pair_usage = key_pair_usage

    def infer_dependencies(self, arguments: List[str]) -> List[str]:
        """Infer dependencies based on the test case arguments."""
        dependencies = psa_information.automatic_dependencies(*arguments,
                                                              prefix=self.dependency_prefix)
        if self.key_bits is not None:
            dependencies = psa_information.finish_family_dependencies(dependencies,
                                                                      self.key_bits)
        if self.key_pair_usage is not None:
            dependencies = psa_information.fix_key_pair_dependencies(dependencies,
                                                                     self.key_pair_usage)
        if 'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE' in dependencies and \
           self.key_bits is not None:
            size_dependency = ('PSA_VENDOR_RSA_GENERATE_MIN_KEY_BITS <= ' +
                               str(self.key_bits))
            dependencies.append(size_dependency)
        return dependencies

    def set_arguments(self, arguments: List[str]) -> None:
        """Set test case arguments and automatically infer dependencies."""
        super().set_arguments(arguments)
        dependencies = self.infer_dependencies(arguments)
        self.skip_if_any_not_implemented(dependencies)
        self.automatic_dependencies.update(dependencies)

    def set_dependencies(self, dependencies: List[str]) -> None:
        """Override any previously added automatic or manual dependencies.

        Also override any previous instruction to skip the test case.
        """
        self.manual_dependencies = dependencies
        self.automatic_dependencies.clear()
        self.skip_reasons = []

    def add_dependencies(self, dependencies: List[str]) -> None:
        """Add manual dependencies."""
        self.manual_dependencies += dependencies

    def get_dependencies(self) -> List[str]:
        # Make the output independent of the order in which the dependencies
        # are calculated by the script. Also avoid duplicates. This makes
        # the output robust with respect to refactoring of the scripts.
        dependencies = set(self.manual_dependencies)
        dependencies.update(self.automatic_dependencies)
        return sorted(dependencies)

    def skip_if_any_not_implemented(self, dependencies: List[str]) -> None:
        """Skip the test case if any of the given dependencies is not implemented."""
        not_implemented = find_dependencies_not_implemented(dependencies)
        for dep in not_implemented:
            self.skip_because('not implemented: ' + dep)
