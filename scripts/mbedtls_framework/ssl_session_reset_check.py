#!/usr/bin/env python3
"""Common code for generating the test code to validate mbedtls_ssl_session_reset().
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import enum
import os
import re
import sys
import typing
import argparse
from typing import Dict, Iterator, List, Tuple

from . import c_parsing_helper
from . import typing_util
from . import build_tree

class FieldsInfo:
    # pylint: disable=too-few-public-methods
    """Default configuration of how each field of the structure must be handled.
    This is meant to be overridden by the caller with branch-specific values.
    """
    KEEP_FIELDS: List[str] = []
    REALLOCATED_FIELDS: List[str] = []
    IGNORE_FIELDS: List[str] = []
    SPECIAL_FIELDS: Dict[str, str] = {}
    NAMED_STRUCTURES: List[str] = []

class ResetBehavior(enum.Enum):
    KEEP = 0        # Kept unchanged before/after the reset
    RESET = 1       # Returned to the initial state (which is not necessarily 0)
    REALLOCATE = 2  # Pointer that gets reallocated
    IGNORE = 3      # Ignored field

class CField():
    # pylint: disable=too-few-public-methods
    """Information about one field of a C struct."""
    name: str
    conditional: str
    reset_behavior: ResetBehavior
    fields_info: FieldsInfo

    def __init__(self, name: str, conditional: str, fields_info: FieldsInfo):
        self.name = name
        self.conditional = conditional
        self.fields_info = fields_info
        if name in fields_info.KEEP_FIELDS:
            self.reset_behavior = ResetBehavior.KEEP
        elif name in fields_info.REALLOCATED_FIELDS:
            self.reset_behavior = ResetBehavior.REALLOCATE
        elif name in fields_info.IGNORE_FIELDS:
            self.reset_behavior = ResetBehavior.IGNORE
        else:
            self.reset_behavior = ResetBehavior.RESET

    def check_value(self) -> str:
        if self.reset_behavior == ResetBehavior.IGNORE:
            return f'/* {self.name} is ignored */'
        raise Exception(f'Reset behavior {self.reset_behavior} not allowed '
                        f'for {self.__class__.__name__} class')

class CScalar(CField):
    # pylint: disable=too-few-public-methods
    """Scalar field. Checked by value."""
    def check_value(self) -> str:
        if self.reset_behavior == ResetBehavior.KEEP:
            return f'TEST_ASSERT(before->{self.name} == after->{self.name});'
        if self.reset_behavior == ResetBehavior.RESET:
            return f'TEST_ASSERT(after->{self.name} == initial.{self.name});'
        return super().check_value()

class CPointer(CScalar):
    # pylint: disable=too-few-public-methods
    """Pointer field. Checked by value. They might be reallocated."""
    def check_value(self) -> str:
        if self.reset_behavior == ResetBehavior.REALLOCATE:
            return f'TEST_ASSERT(after->{self.name} != NULL);'
        return super().check_value()

class CArray(CField):
    # pylint: disable=too-few-public-methods
    """Array field. Checked by memory comparison."""
    def check_value(self) -> str:
        if self.reset_behavior == ResetBehavior.KEEP:
            return (f'TEST_MEMORY_COMPARE(before->{self.name}, '
                    f'sizeof(before->{self.name}), after->{self.name}, '
                    f'sizeof(after->{self.name}));')
        if self.reset_behavior == ResetBehavior.RESET:
            return (f'TEST_MEMORY_COMPARE(after->{self.name}, '
                    f'sizeof(after->{self.name}), initial.{self.name}, '
                    f'sizeof(initial.{self.name}));')
        return super().check_value()

class CStructure(CField):
    # pylint: disable=too-few-public-methods
    """Named structure field. Checked by memory comparison."""
    def check_value(self) -> str:
        if self.reset_behavior == ResetBehavior.KEEP:
            return (f'TEST_MEMORY_COMPARE(&(before->{self.name}), '
                    f'sizeof(before->{self.name}), &(after->{self.name}), '
                    f'sizeof(after->{self.name}));')
        if self.reset_behavior == ResetBehavior.RESET:
            return (f'TEST_MEMORY_COMPARE(&(after->{self.name}), '
                    f'sizeof(after->{self.name}), &(initial.{self.name}), '
                    f'sizeof(initial.{self.name}));')
        return super().check_value()

class CSpecial(CField):
    # pylint: disable=too-few-public-methods
    """Field with a custom check. No behavior handing here because we know
    what to expect from this field."""
    def check_value(self) -> str:
        return self.fields_info.SPECIAL_FIELDS[self.name]

class CStruct:
    # pylint: disable=too-few-public-methods
    """Information about the fields of a C struct."""

    _PREPROCESSOR_RE = re.compile(r'\s*#\s*(\w+)\s*(.*)')
    _STRUCT_RE = re.compile(r'struct\s+(\w+)\s*{')
    _FIELD_RE = re.compile(r'\s*([^;]+);')
    _PRIVATE_FIELD_RE = re.compile(r'MBEDTLS_PRIVATE\((\w+)\)')
    _BARE_FIELD_RE = re.compile(r'[\t *](\w+)\Z')
    _ARRAY_RE = re.compile(r'\[(\w+)\]')
    _NON_BLANK_RE = re.compile(r'.*\S')

    def _parse_field(self, declaration: str, conditionals: List[str]) -> CField:
        """Return the CField object describing the given field declaration."""
        # Note that this simplistic parsing finds fields in inline
        # sub-structs, unions and enums.
        m = self._PRIVATE_FIELD_RE.search(declaration)
        if not m:
            m = self._BARE_FIELD_RE.search(declaration)
        if not m:
            raise Exception(f'Field name not found in "{declaration}"')
        name = m.group(1)
        conditional = ' && '.join(conditionals)
        # Check for special fields
        if name in self.fields_info.SPECIAL_FIELDS:
            return CSpecial(name, conditional, self.fields_info)
        # Check for named structures
        if name in self.fields_info.NAMED_STRUCTURES:
            return CStructure(name, conditional, self.fields_info)
        # Check for pointer
        if '*' in declaration:
            return CPointer(name, conditional, self.fields_info)
        # Check for array
        m = self._ARRAY_RE.search(declaration)
        if m:
            return CArray(name, conditional, self.fields_info)
        # If we get here then the field is a scalar
        return CScalar(name, conditional, self.fields_info)

    @staticmethod
    def _continue_parsing_preprocessor(argument: str, line: str,
                                       lines: Iterator[Tuple[int, str]]) -> str:
        """Append continuation lines of preprocesssor directive."""
        while line.endswith('\\'):
            try:
                argument = argument[:-1] + ' ' + next(lines)[1]
            except StopIteration:
                break
        return argument

    def _structure_fields(self,
                          lines: Iterator[Tuple[int, str]],
                          struct_name: str) -> Iterator[CField]:
        """Yield a CField object for each field of the given structure."""
        found_start = False
        for num, line in lines:
            m = self._STRUCT_RE.match(line)
            if m and m.group(1) == struct_name:
                found_start = True
                break
        if not found_start:
            raise Exception(f'Definition of struct {struct_name} not found')
        conditionals: List[str] = []
        for num, line in lines:
            if line.startswith('}'):
                return
            m = self._PREPROCESSOR_RE.match(line)
            if m:
                argument = m.group(2)
                if line.endswith('\\'):
                    argument = self._continue_parsing_preprocessor(argument, line, lines)
                directive = m.group(1)
                if directive == 'if':
                    conditionals.append('(' + argument + ')')
                elif directive == 'endif':
                    del conditionals[-1]
                else:
                    raise Exception(f'Unsupported directive #{directive} at line {num}')
                continue
            m = self._FIELD_RE.match(line)
            if m:
                yield self._parse_field(m.group(1), conditionals)
                continue
            m = self._NON_BLANK_RE.match(line)
            if m:
                raise Exception(f'Failed to parse non-empty line {num}. Content is: {line}')
        raise Exception(f'End of definition of struct {struct_name} not found')

    def __init__(self, file_name: str, struct_name: str,
                 fields_info: FieldsInfo) -> None:
        """Parse a structure definition in a C source file."""
        self.fields_info = fields_info
        lines = c_parsing_helper.read_logical_lines(file_name)
        self.fields = list(self._structure_fields(lines, struct_name))


class SSLContextStruct(CStruct):
    # pylint: disable=too-few-public-methods
    """Information about the fields of struct mbedtls_ssl_context."""

    def __init__(self, out: typing_util.Writable,
                 fields_info: FieldsInfo) -> None:
        self.out = out
        super().__init__('include/mbedtls/ssl.h', 'mbedtls_ssl_context',
                         fields_info)

    def write_check_function(self) -> None:
        """Write the generated context-checking function to the output."""
        out = self.out
        out.write(f"""\
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * The following function was automatically generated through the script
 * {sys.argv[0]}.
 */

#include <test/ssl_helpers.h>
#include <test/ssl_helpers_internal.h>
#include "mbedtls/psa_util.h"
#include <test/macros.h>

#include <limits.h>

#if defined(MBEDTLS_SSL_TLS_C)

int mbedtls_test_ssl_check_context_after_session_reset(mbedtls_ssl_context *before,
                                                       mbedtls_ssl_context *after)
{{
    mbedtls_ssl_context initial;
    int ret = -1;

    /* Create a freshly initialized SSL context*/
    memset(&initial, 0, sizeof(initial));
    mbedtls_ssl_init(&initial);
    TEST_EQUAL(mbedtls_ssl_setup(&initial, after->conf), 0);

    /* *INDENT-OFF* */
""")
        for field in self.fields:
            if field.conditional:
                out.write(f'#if {field.conditional}\n')
            out.write(f'    {field.check_value()}\n')
            if field.conditional:
                out.write('#endif\n')
        out.write(f"""\
    /* *INDENT-ON* */

    ret = 0;

exit:
    mbedtls_ssl_free(&initial);

    return ret;
}}

#endif /* MBEDTLS_SSL_TLS_C */
""")


def main(fields_info: FieldsInfo):
    if not build_tree.looks_like_mbedtls_root(os.curdir):
        raise Exception("The script must be launched from the root path of Mbed TLS")
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('-o', dest='output_file',
                            help='Generated output file',
                            default='tests/src/ssl_context_reset_verifier.c')
    parsed_args = arg_parser.parse_args()

    output_file = parsed_args.output_file
    with open(output_file, 'wt') as out:
        ssl_context = SSLContextStruct(out, fields_info)
        ssl_context.write_check_function()
