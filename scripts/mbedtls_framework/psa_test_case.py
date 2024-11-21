"""Generate test cases for PSA API calls, with automatic dependencies.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

from typing import List, Set

from . import psa_information
from . import test_case


class TestCase(test_case.TestCase):
    """A PSA test case with automatically inferred dependencies.

    For mechanisms like ECC curves where the support status includes
    the key bit-size, this class assumes that only one bit-size is
    involved in a given test case.
    """

    def __init__(self) -> None:
        super().__init__()
        del self.dependencies
        self.manual_dependencies = [] #type: List[str]
        self.automatic_dependencies = set() #type: Set[str]

    @staticmethod
    def infer_dependencies(_arguments: List[str]) -> List[str]:
        """Infer dependencies based on the test case arguments."""
        return [] # not implemented yet

    def set_arguments(self, arguments: List[str]) -> None:
        """Set test case arguments and automatically infer dependencies."""
        super().set_arguments(arguments)
        self.automatic_dependencies.update(self.infer_dependencies(arguments))

    def set_dependencies(self, dependencies: List[str]) -> None:
        """Override any previously added automatic or manual dependencies."""
        self.manual_dependencies = dependencies
        self.automatic_dependencies.clear()

    def add_dependencies(self, dependencies: List[str]) -> None:
        """Add manual dependencies."""
        self.manual_dependencies += dependencies

    def get_dependencies(self) -> List[str]:
        return sorted(self.automatic_dependencies) + self.manual_dependencies

    def skip_if_any_not_implemented(self, dependencies: List[str]) -> None:
        """Skip the test case if any of the given dependencies is not implemented."""
        not_implemented = psa_information.find_dependencies_not_implemented(dependencies)
        if not_implemented:
            self.add_dependencies(['DEPENDENCY_NOT_IMPLEMENTED_YET'])
