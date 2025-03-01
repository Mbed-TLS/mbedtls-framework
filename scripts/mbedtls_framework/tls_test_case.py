"""Library for constructing an Mbed TLS ssl-opt test case.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import enum
import re
from typing import List

from . import typing_util


class TestCase:
    """Data about an ssl-opt test case."""
    #pylint: disable=too-few-public-methods

    def __init__(self, description: str) -> None:
        # List of shell snippets to call before run_test, typically
        # calls to requires_xxx functions.
        self.requirements = [] #type: List[str]
        # Test case description (first argument to run_test).
        self.description = description
        # Client command line.
        # This will be placed directly inside double quotes in the shell script.
        self.client = '$P_CLI'
        # Server command line.
        # This will be placed directly inside double quotes in the shell script.
        self.server = '$P_SRV'
        # Expected client exit code.
        self.exit_code = 0
        # BRE for text that must be present in the client log (run_test -c).
        self.wanted_client_patterns = [] #type: List[str]
        # BRE for text that must be present in the server log (run_test -s).
        self.wanted_server_patterns = [] #type: List[str]
        # BRE for text that must not be present in the client log (run_test -C).
        self.forbidden_client_patterns = [] #type: List[str]
        # BRE for text that must not be present in the server log (run_test -S).
        self.forbidden_server_patterns = [] #type: List[str]

    @staticmethod
    def _quote(raw: str) -> str:
        """Quote the given string for sh.

        Use double quotes, because that's currently the norm in ssl-opt.sh.
        """
        return '"' + re.sub(r'([$"\\`])', r'\\\1', raw) + '"'

    def write(self, out: typing_util.Writable) -> None:
        """Write the test case to the specified file."""
        for req in self.requirements:
            out.write(req + '\n')
        out.write(f'run_test    {self._quote(self.description)} \\\n')
        out.write(f'            "{self.server}" \\\n')
        out.write(f'            "{self.client}" \\\n')
        out.write(f'            {self.exit_code}')
        for pat in self.wanted_server_patterns:
            out.write(' \\\n            -s ' + self._quote(pat))
        for pat in self.forbidden_server_patterns:
            out.write(' \\\n            -S ' + self._quote(pat))
        for pat in self.wanted_client_patterns:
            out.write(' \\\n            -c ' + self._quote(pat))
        for pat in self.forbidden_client_patterns:
            out.write(' \\\n            -C ' + self._quote(pat))
        out.write('\n\n')


class Side(enum.Enum):
    CLIENT = 0
    SERVER = 1

class Version(enum.Enum):
    TLS12 = 2
    TLS13 = 3
