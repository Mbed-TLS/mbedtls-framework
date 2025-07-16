"""Generate C preprocessor code to check for bad configurations.
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import enum
import os
import sys
import textwrap
import typing
from typing import List, Optional

from . import build_tree
from . import typing_util


class Position(enum.Enum):
    BEFORE = 0
    AFTER = 1


class Checker:
    """Description of checks for one option."""

    def __init__(self, name: str, suggestion: str = '') -> None:
        """Construct a checker for the given preprocessor macro name.

        If suggestion is given, it is appended to the error message.
        It should be a short sentence intended for human readers.
        This sentence follows a sentence like "<macro_name> is not
        a valid configuration option".
        """
        self.name = name
        self.suggestion = suggestion

    def _basic_message(self) -> str:
        """The first sentence of the message to display on error.

        It should end with a full stop or other sentence-ending punctuation.
        """
        return f'{self.name} is not a valid configuration option.'

    def message(self) -> str:
        """The message to display on error."""
        message = self._basic_message()
        if self.suggestion:
            message += ' Suggestion: ' + self.suggestion
        return message

    def _quoted_message(self) -> str:
        """Quote message() in double quotes."""
        return ('"' +
                str.replace(str.replace(self.message(),
                                        '\\', '\\\\'),
                            '"', '\\"') +
                '"')

    def before(self, _prefix: str) -> str:
        #pylint: disable=no-self-use
        """C code to inject before including the config."""
        return ''

    def after(self, _prefix: str) -> str:
        """C code to inject before including the config."""
        return f'''
        #if defined({self.name})
        #  error {self._quoted_message()}
        #endif
        '''

    def code(self, position: Position, prefix: str) -> str:
        """C code to inject at the given position.

        Use the given prefix for auxiliary macro names.
        """
        if position == Position.BEFORE:
            return textwrap.dedent(self.before(prefix))
        elif position == Position.AFTER:
            return textwrap.dedent(self.after(prefix))
        else:
            raise ValueError(position)


class Internal(Checker):
    """Checker for an internal-only option."""


class SubprojectInternal(Checker):
    """Checker for an internal macro of a subproject."""

    # meant to be overridden in child classes
    SUBPROJECT = None #type: Optional[str]

    def __init__(self, name: str, suggestion: str = '',
                 subproject: Optional[str] = None) -> None:
        super().__init__(name, suggestion)
        if subproject is not None:
            self.subproject = subproject
        elif self.SUBPROJECT is not None:
            self.subproject = self.SUBPROJECT
        else:
            raise ValueError('No subproject specified for ' + name)

    def _basic_message(self) -> str:
        return f'{self.name} is an internal macro of {self.subproject} and may not be configured.'

    def before(self, prefix: str) -> str:
        return f'''
        #if defined({self.name})
        #  define {prefix}_WASSET_{self.name} 1
        #else
        #  define {prefix}_WASSET_{self.name} 0
        #endif
        #undef {self.name}
        '''

    def after(self, prefix: str) -> str:
        return f'''
        #if defined({self.name})
        #  error {self._quoted_message()}
        #endif
        #if {prefix}_WASSET_{self.name}
        #  define {self.name}
        #endif
        #undef {prefix}_WASSET_{self.name}
        '''


class SubprojectOption(SubprojectInternal):
    """Checker for a configuration option of a subproject."""

    def __init__(self, name: str, subproject: Optional[str] = None) -> None:
        super().__init__(name, subproject=subproject)

    def _basic_message(self) -> str:
        return f'{self.name} must be configured in f{self.subproject}.'

    def after(self, prefix: str) -> str:
        return f'''
        #if defined({self.name}) && !{prefix}_WASSET_{self.name}
        #  error {self._quoted_message()}
        #endif
        #if {prefix}_WASSET_{self.name}
        #  define {self.name}
        #endif
        #undef {prefix}_WASSET_{self.name}
        '''


class Removed(Checker):
    """Checker for an option that has been removed."""

    def __init__(self, name: str, version: str, suggestion: str = '') -> None:
        super().__init__(name, suggestion)
        self.version = version

    def _basic_message(self) -> str:
        """The first sentence of the message to display on error.

        It should end with a full stop or other sentence-ending punctuation.
        """
        return f'{self.name} was removed in version {self.version}.'


class BranchData(typing.NamedTuple):
    """The relevant aspects of the configuration on a branch."""

    # Subdirectory where the generated headers will be located.
    header_directory: str

    # Prefix used to the generated headers' basename.
    header_prefix: str

    # Prefix used for C preprocessor macros.
    project_cpp_prefix: str

    # Options to check
    checkers: List[Checker]


class HeaderGenerator:
    """Generate a header to include before or after the user config."""

    def __init__(self, branch_data: BranchData, position: Position) -> None:
        self.branch_data = branch_data
        self.position = position
        self.prefix = branch_data.project_cpp_prefix + '_CONFIG_CHECK'
        self.bypass_checks = self.prefix + '_BYPASS'

    @staticmethod
    def filename(root: str,
                 branch_data: BranchData,
                 position: Position) -> str:
        """The file name for this header, under the given root."""
        suffix = f'config_check_{position.name.lower()}.h'
        return os.path.join(root,
                            branch_data.header_directory,
                            branch_data.header_prefix + suffix)

    def write_stanza(self, out: typing_util.Writable, checker: Checker) -> None:
        """Write the part of the output corresponding to one config option."""
        code = checker.code(self.position, self.prefix)
        out.write(code)

    def write_content(self, out: typing_util.Writable) -> None:
        """Write the output for all config options to be processed."""
        for checker in self.branch_data.checkers:
            self.write_stanza(out, checker)

    def write(self, root: str) -> None:
        """Write the whole output file."""
        filename = self.filename(root, self.branch_data, self.position)
        with open(filename, 'w') as out:
            out.write(f"""\
/* {os.path.basename(filename)}: checks before including the user configuration file. */
/* Automatically generated by {os.path.basename(sys.argv[0])}. Do not edit! */

#if !defined({self.bypass_checks})

/* *INDENT-OFF* */
""")
            self.write_content(out)
            out.write(f"""
/* *INDENT-ON* */

#endif /* !defined({self.bypass_checks}) */

/* End of automatically generated {os.path.basename(filename)} */
""")


def generate_header_files(root: str, branch_data: BranchData) -> None:
    """Generate the header files to include before and after *config.h."""
    before_generator = HeaderGenerator(branch_data, Position.BEFORE)
    before_generator.write(root)
    after_generator = HeaderGenerator(branch_data, Position.AFTER)
    after_generator.write(root)


def main(branch_data: BranchData) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true',
                        help='List generated files and exit')
    options = parser.parse_args()
    root = build_tree.guess_project_root()
    if options.list:
        for position in [Position.BEFORE, Position.AFTER]:
            print(HeaderGenerator.filename(root, branch_data, position))
        return
    generate_header_files(root, branch_data)
