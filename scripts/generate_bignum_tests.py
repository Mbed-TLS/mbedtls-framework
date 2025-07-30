#!/usr/bin/env python3
"""Generate test data for bignum functions.

With no arguments, generate all test data. With non-option arguments,
generate only the specified files.

Class structure:

Child classes of test_data_generation.BaseTarget (file targets) represent an output
file. These indicate where test cases will be written to, for all subclasses of
this target. Multiple file targets should not reuse a `target_basename`.

Each subclass derived from a file target can either be:
  - A concrete class, representing a test function, which generates test cases.
  - An abstract class containing shared methods and attributes, not associated
        with a test function. An example is BignumOperation, which provides
        common features used for bignum binary operations.

Both concrete and abstract subclasses can be derived from, to implement
additional test cases (see BignumCmp and BignumCmpAbs for examples of deriving
from abstract and concrete classes).


Adding test case generation for a function:

A subclass representing the test function should be added, deriving from a
file target such as BignumTarget. This test class must set/implement the
following:
  - test_function: the function name from the associated .function file.
  - test_name: a descriptive name or brief summary to refer to the test
        function.
  - arguments(): a method to generate the list of arguments required for the
        test_function.
  - generate_function_tests(): a method to generate TestCases for the function.
        This should create instances of the class with required input data, and
        call `.create_test_case()` to yield the TestCase.

Additional details and other attributes/methods are given in the documentation
of BaseTarget in test_data_generation.py.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import sys
import math

from abc import ABCMeta
from typing import List

from mbedtls_framework import test_data_generation
from mbedtls_framework import bignum_common
# Import modules containing additional test classes
# Test function classes in these modules will be registered by
# the framework
from mbedtls_framework import bignum_core, bignum_mod_raw, bignum_mod # pylint: disable=unused-import

class BignumTarget(test_data_generation.BaseTarget):
    #pylint: disable=too-few-public-methods
    """Target for bignum (legacy) test case generation."""
    target_basename = 'test_suite_bignum.generated'


class BignumOperation(bignum_common.OperationCommon, BignumTarget,
                      metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Common features for bignum operations in legacy tests."""
    unique_combinations_only = True
    input_values = [
        "", "0", "-", "-0",
        "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ]

    def description_suffix(self) -> str:
        #pylint: disable=no-self-use # derived classes need self
        """Text to add at the end of the test case description."""
        return ""

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B, where symbol
        is used to represent the operation. Descriptions of each value are
        generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{} {} {}".format(
                self.value_description(self.arg_a),
                self.symbol,
                self.value_description(self.arg_b)
            )
            description_suffix = self.description_suffix()
            if description_suffix:
                self.case_description += " " + description_suffix
        return super().description()

    @staticmethod
    def value_description(val) -> str:
        """Generate a description of the argument val.

        This produces a simple description of the value, which is used in test
        case naming to add context.
        """
        if val == "":
            return "0 (null)"
        if val == "-":
            return "negative 0 (null)"
        if val == "0":
            return "0 (1 limb)"

        if val[0] == "-":
            tmp = "negative"
            val = val[1:]
        else:
            tmp = "positive"
        if val[0] == "0":
            tmp += " with leading zero limb"
        elif len(val) > 10:
            tmp = "large " + tmp
        return tmp


class BignumCmp(BignumOperation):
    """Test cases for bignum value comparison."""
    count = 0
    test_function = "mpi_cmp_mpi"
    test_name = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_a, val_b) -> None:
        super().__init__(val_a, val_b)
        self._result = int(self.int_a > self.int_b) - int(self.int_a < self.int_b)
        self.symbol = ["<", "==", ">"][self._result + 1]

    def result(self) -> List[str]:
        return [str(self._result)]


class BignumCmpAbs(BignumCmp):
    """Test cases for absolute bignum value comparison."""
    count = 0
    test_function = "mpi_cmp_abs"
    test_name = "MPI compare (abs)"

    def __init__(self, val_a, val_b) -> None:
        super().__init__(val_a.strip("-"), val_b.strip("-"))


class BignumInvMod(BignumOperation):
    """Test cases for bignum modular inverse."""
    count = 0
    symbol = "^-1 mod"
    test_function = "mpi_inv_mod"
    test_name = "MPI inv_mod"
    # The default values are not very useful here, so clear them.
    input_values = [] # type: List[str]
    input_cases = bignum_common.combination_two_lists(
        # Input values for A
        bignum_common.expand_list_negative([
            "aa4df5cb14b4c31237f98bd1faf527c283c2d0f3eec89718664ba33f9762907c",
            "f847e7731a2687c837f6b825f2937d997bf66814d3db79b27b",
            "2ec0888f",
            "22fbdf4c",
            "32cf9a75",
        ]),
        # Input values for N - must be positive.
        [
            "fffbbd660b94412ae61ead9c2906a344116e316a256fd387874c6c675b1d587d",
            "2fe72fa5c05bc14c1279e37e2701bd956822999f42c5cbe84",
            "2ec0888f",
            "22fbdf4c",
            "34d0830",
            "364b6729",
            "14419cd",
        ],
    )

    def __init__(self, val_a: str, val_b: str) -> None:
        super().__init__(val_a, val_b)
        if math.gcd(self.int_a, self.int_b) == 1:
            self._result = bignum_common.invmod_positive(self.int_a, self.int_b)
        else:
            self._result = -1 # No modular inverse.

    def description_suffix(self) -> str:
        suffix = ": "
        # Assuming N (int_b) is always positive, compare absolute values,
        # but only print the absolute value bars when A is negative.
        a_str = "A" if (self.int_a >= 0) else "|A|"
        if abs(self.int_a) > self.int_b:
            suffix += f"{a_str}>N"
        elif abs(self.int_a) < self.int_b:
            suffix += f"{a_str}<N"
        else:
            suffix += f"{a_str}=N"
        if self.int_a < 0:
            suffix += ", A<0"
        if self._result == -1:
            suffix += ", no inverse"
        return suffix

    def result(self) -> List[str]:
        if self._result == -1: # No modular inverse.
            return [bignum_common.quote_str("0"), "MBEDTLS_ERR_MPI_NOT_ACCEPTABLE"]
        return [bignum_common.quote_str("{:x}".format(self._result)), "0"]


class BignumGCD(BignumOperation):
    """Test cases for greatest common divisor."""
    count = 0
    symbol = "GCD"
    test_function = "mpi_gcd"
    test_name = "GCD"
    # The default values are not very useful here, so overwrite them.
    input_values = bignum_common.expand_list_negative([
        "3c094fd6b36ee4902c8ba84d13a401def90a2130116dad3361",
        "b2b06ebe14a185a83d5d2d7bddd1dd0e05e800d6b914fbed4e",
        "203265b387",
        "9bc8e63852",
        "100000000",
        "300000000",
        "500000000",
        "50000",
        "30000",
        "1",
        "2",
        "3",
        ])

    def __init__(self, val_a: str, val_b: str) -> None:
        super().__init__(val_a, val_b)
        # We always expect as postivite result as the test data
        # does not contain zero.
        self._result = math.gcd(self.int_a, self.int_b)

    def description_suffix(self) -> str:
        suffix = ": "
        if abs(self.int_a) > abs(self.int_b):
            suffix += "|A|>|B|"
        elif abs(self.int_a) < abs(self.int_b):
            suffix += "|A|<|B|"
        else:
            suffix += "|A|=|B|"
        if self.int_a < 0:
            suffix += ", A<0"
        if self.int_b < 0:
            suffix += ", B<0"
        suffix += ", A even" if (self.int_a % 2 == 0) else ", A odd"
        suffix += ", B even" if (self.int_b % 2 == 0) else ", B odd"
        return suffix

    def result(self) -> List[str]:
        return [bignum_common.quote_str("{:x}".format(self._result))]


class BignumAdd(BignumOperation):
    """Test cases for bignum value addition."""
    count = 0
    symbol = "+"
    test_function = "mpi_add_mpi"
    test_name = "MPI add"
    input_cases = bignum_common.combination_pairs(
        [
            "1c67967269c6", "9cde3",
            "-1c67967269c6", "-9cde3",
        ]
    )

    def __init__(self, val_a: str, val_b: str) -> None:
        super().__init__(val_a, val_b)
        self._result = self.int_a + self.int_b

    def description_suffix(self) -> str:
        if (self.int_a >= 0 and self.int_b >= 0):
            return "" # obviously positive result or 0
        if (self.int_a <= 0 and self.int_b <= 0):
            return "" # obviously negative result or 0
        # The sign of the result is not obvious, so indicate it
        return ", result{}0".format('>' if self._result > 0 else
                                    '<' if self._result < 0 else '=')

    def result(self) -> List[str]:
        return [bignum_common.quote_str("{:x}".format(self._result))]

if __name__ == '__main__':
    # Use the section of the docstring relevant to the CLI as description
    test_data_generation.main(sys.argv[1:], "\n".join(__doc__.splitlines()[:4]))
