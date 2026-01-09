"""Read and format test data from NIST ACVP-Server.

This module is designed to parse JSON files provided in
https://github.com/usnistgov/ACVP-Server
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import json
import os
import re
import sys
import typing
from typing import Dict, List, Union

from . import typing_util


class TestCaseFields():
    """Augmented test case fields.

    You can append the following suffix to fields:
    * ``/8``: divide the value by 8.
    """
    #pylint: disable=too-few-public-methods

    def __init__(self, base: Dict[str, Union[str, int]]) -> None:
        self.base = base

    _DIVIDE_RE = re.compile(r'(\w+)/([1-9][0-9]*)\Z')

    def __getitem__(self, key: str) -> Union[str, int]:
        """Augmented key lookup.

        See the class description for details.
        """
        m = self._DIVIDE_RE.match(key)
        if m:
            field = m.group(1)
            denominator = int(m.group(2))
            value = self.base[field]
            if not isinstance(value, int):
                raise TypeError(f"Not an integer-valued field: \"{field}\"")
            if value % denominator != 0:
                raise TypeError(f"Not a multiple of {denominator}: [\"field\"] = {value}")
            return value // denominator
        return self.base[key]


class TestCase:
    """One test case from ACVP data."""

    def __init__(self,
                 data: Dict[str, Union[str, int]],
                 group_number: int) -> None:
        #pylint: disable=invalid-name # follow the style of the data
        self.group = group_number
        self._data = data
        self.tcId = data['tcId']

    def get_int(self, field: str) -> int:
        """Get an integer-valued field."""
        value = self._data[field]
        if not isinstance(value, int):
            raise TypeError(f"Not an integer-valued field: \"field\"")
        return value

    def get_str(self, field: str) -> str:
        """Get a string-valued field."""
        value = self._data[field]
        if not isinstance(value, str):
            raise TypeError(f"Not a string-valued field: \"field\"")
        return value

    def get_bytes(self, field: str) -> bytes:
        """Parse a string-valued field as a hex dump."""
        return bytes.fromhex(self.get_str(field))

    def lengths_are_octets(self) -> bool:
        """Whether all lengths in a test case are a mulitple of 8."""
        for field in self._data:
            if not (field == 'len' or field.endswith('Len')):
                continue
            if not isinstance(self._data[field], int):
                continue
            if self._data[field] % 8 != 0:
                return False
        return True

    def format(self,
               description_template: str,
               dependencies: str,
               call_template: str) -> str:
        """Format a test case to standard output using the given templates.

        All features of the Python `str.format()` method are available.
        In addition, the field name can have custom suffixes, provided
        by the `TestCaseFields` class.
        """
        # This is a convenience function for writing ad hoc (long) one-liners,
        # so we do some ad hoc formatting rather than use the test_case
        # module. Scripts that are checked into the repository should rather
        # use test_case.py (or better, psa_test_case.py if applicable).
        fields = TestCaseFields(self._data)
        description = description_template.format_map(fields)
        depends_on = f'depends_on:{dependencies}\n' if dependencies else ''
        call = call_template.format_map(fields)
        return f'{description}\n{depends_on}{call}\n'


# We use _Self in type annotations inside the ACVP calss. Pylint 2.4 doesn't
# understand the scope rules for type annotations, so it complains that
# _Self isn't defined unless we define it at the top level.
_Self = None #pylint: disable=invalid-name

class ACVP:
    """Test data from ACVP.

    The expected input is an internalProjection.json file from
    gen-val/json-files/* in https://github.com/usnistgov/ACVP-Server .
    """

    # Modern code can use typing.Self from PEP673, but we use older mypy
    # and python that predate it.
    _Self = typing.TypeVar('_Self', bound='ACVP')

    def __init__(self) -> None:
        self.tests = [] #type: List[TestCase]

    def looks_usable(self, tc: TestCase) -> bool:
        """Whether a test case looks usable.

        The default implementation checks that length fields are a
        multiple of 8, since these are bit-lengths, but most of the world,
        including us, only cares about octet strings.
        """
        #pylint: disable=no-self-use # Child classes may override this method
        if not tc.lengths_are_octets():
            return False
        return True

    def add_group(self,
                  group: Dict[str, typing.Any]) -> None:
        """Add a group of tests."""
        group_number = group['tgId']
        for item in group['tests']:
            tc = TestCase(item, group_number)
            if not self.looks_usable(tc):
                continue
            self.tests.append(tc)

    def load(self, input_: typing_util.Readable) -> None:
        """Load JSON data from a text stream.

        This should be an ACVP ``internalProjection.json`` file.
        """
        data = json.load(input_)
        for group in data['testGroups']:
            self.add_group(group)

    def load_file(self, filename: str) -> None:
        """Load ACVP test cases from a file.

        If filename is a directory, read ``internalProjection.json``.
        """
        if os.path.isdir(filename):
            filename = os.path.join(filename, 'internalProjection.json')
        with open(filename) as input_:
            self.load(input_)

    def remove(self: _Self,
               predicate: typing.Callable[[TestCase], bool]) -> _Self:
        """Remove test cases for which predicate is true.

        Acts in place. Returns self for chaining.
        """
        self.tests = [tc for tc in self.tests if not predicate(tc)]
        return self

    def select(self: _Self,
               predicate: typing.Callable[[TestCase], bool]) -> _Self:
        """Select test cases for which predicate is true.

        Return a new instance, leaving the original intact.
        """
        result = self.__class__()
        result.tests = [tc for tc in self.tests if predicate(tc)]
        return result

    def sort(self: _Self, key: typing.Callable[[TestCase], typing.Any]) -> _Self:
        """Sort the test cases according to the given key.

        Acts in place. Returns self for chaining.
        """
        self.tests.sort(key=key)
        return self

    def print(self,
              description_template: str,
              dependencies: str,
              call_template: str) -> None:
        """Print a test case to standard output using the given templates."""
        for tc in self.tests:
            one = tc.format(description_template, dependencies, call_template)
            sys.stdout.write(one + '\n')


def from_file(filename: str) -> ACVP:
    """Load ACVP test cases from a file.

    If filename is a directory, read ``internalProjection.json``.
    """
    tests = ACVP()
    tests.load_file(filename)
    return tests


def cli() -> ACVP:
    """Load ACVP test cases based on the command line arguments."""
    tests = ACVP()
    for filename in sys.argv[1:]:
        tests.load_file(filename)
    return tests

def cli_eval() -> None:
    """Load ACVP test cases and process them based on the command line.

    Command line syntax::

        python -m mbedtls_framework.acvp_parser \
               'tests.print("Foo ACVP #{tcId}", "", "foo:\"{msg}\":\"{out}\"")' \
               .../AVCP-Server/gen-val/json-files/DIR
    """
    code = sys.argv[1]
    tests = ACVP()
    for filename in sys.argv[2:]:
        tests.load_file(filename)
    exec(code) #pylint: disable=exec-used

if __name__ == '__main__':
    cli_eval()
