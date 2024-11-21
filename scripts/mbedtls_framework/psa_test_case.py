"""Generate test cases for PSA API calls, with automatic dependencies.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

from . import test_case


class TestCase(test_case.TestCase):
    """A PSA test case with automatically inferred dependencies.

    For mechanisms like ECC curves where the support status includes
    the key bit-size, this class assumes that only one bit-size is
    involved in a given test case.
    """

    def __init__(self) -> None:
        super().__init__()
