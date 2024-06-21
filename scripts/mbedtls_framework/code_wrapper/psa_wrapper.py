#!/usr/bin/env python3
"""Generate wrapper functions for PSA function calls.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import itertools
import os
from typing import Any, Iterator, List, Dict, Collection, Optional, Tuple

from mbedtls_framework import build_tree
from mbedtls_framework import c_parsing_helper
from mbedtls_framework import c_wrapper_generator
from mbedtls_framework import typing_util

from mbedtls_framework.code_wrapper.psa_buffer import BufferParameter
from textwrap import dedent

DEFAULTS = {
    "input_headers" : ['crypto.h', 'crypto_extra.h'],
    "define_guards" : ["MBEDTLS_PSA_CRYPTO_C", "MBEDTLS_TEST_HOOKS", "!RECORD_PSA_STATUS_COVERAGE_LOG"],
    "skip_list" : frozenset([
        'mbedtls_psa_external_get_random', # not a library function
        'psa_get_key_domain_parameters', # client-side function
        'psa_get_key_slot_number', # client-side function
        'psa_key_derivation_verify_bytes', # not implemented yet
        'psa_key_derivation_verify_key', # not implemented yet
        'psa_set_key_domain_parameters', # client-side function
    ]),
    # PAKE stuff: not implemented yet
    "not_implemented": frozenset([
        'psa_crypto_driver_pake_inputs_t *',
        'psa_pake_cipher_suite_t *',
    ]),
    "function_guards": {
        'mbedtls_psa_register_se_key': 'defined(MBEDTLS_PSA_CRYPTO_SE_C)',
        'mbedtls_psa_inject_entropy': 'defined(MBEDTLS_PSA_INJECT_ENTROPY)',
        'mbedtls_psa_external_get_random': 'defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)',
        'mbedtls_psa_platform_get_builtin_key': 'defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)',
        'psa_crypto_driver_pake_get_cipher_suite' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_password' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_password_len' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_peer' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_peer_len' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_user' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_crypto_driver_pake_get_user_len' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_abort' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_get_implicit_key' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_input' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_output' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_set_password_key' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_set_peer' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_set_role' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_set_user' : 'defined(PSA_WANT_ALG_SOME_PAKE)',
        'psa_pake_setup' : 'defined(PSA_WANT_ALG_SOME_PAKE)'
    }
}

class PSAWrapper(c_wrapper_generator.Base):
    """Generate a C source file containing wrapper functions for PSA Crypto API calls."""

    _WRAPPER_NAME_PREFIX = 'mbedtls_test_wrap_'
    _WRAPPER_NAME_SUFFIX = ''

    _PSA_WRAPPER_INCLUDES = ['<psa/crypto.h>']

    def __init__(self,
                 output_h_f: str,
                 output_c_f: str,
                 in_headers:  Collection[str] = DEFAULTS["input_headers"],
                 config: Dict[str, Any]= DEFAULTS) -> None:

        super().__init__()
        self._FUNCTION_GUARDS = super()._FUNCTION_GUARDS.copy()
        self.in_headers = in_headers
        self.out_c_f = output_c_f
        self.out_h_f = output_h_f

        self.mbedtls_root = build_tree.guess_mbedtls_root()
        self.read_config(config)

        if in_headers:
            self.read_headers(in_headers)

    def read_config(self, cfg: Dict[str, Any])-> None:
        """Configure instance's parameters based on a module specific default config """

        self._CPP_GUARDS = PSAWrapper.parse_def_guards(cfg["define_guards"])
        self._SKIP_FUNCTIONS = cfg["skip_list"]
        self._FUNCTION_GUARDS.update(cfg["function_guards"]) # type: ignore[arg-type]
        self._NOT_IMPLEMENTED = cfg["not_implemented"]

    def read_headers(self, headers: Collection[str]) -> None:
        """ Reads functions from source header files into a Dict[str, FunctionInfo] """

        for header_name in headers:
            header_path = self.rel_path(header_name)
            c_parsing_helper.read_function_declarations(self.functions, header_path)

    def rel_path(self, filename: str, path_list: List[str] = ['include', 'psa']) -> str:
        """ Return the estimated path in relationship to the.
            mbedtls_root. The method allows overriding the targetted sub-directory.
            Currently the default is set to mbedtls_root/include/psa """

        # Temporary, while Mbed TLS does not just rely on the TF-PSA-Crypto
        # build system to build its crypto library. When it does, the first
        # case can just be removed.
        if os.path.isdir(os.path.join(self.mbedtls_root, 'tf-psa-crypto')):
            path_list = ['tf-psa-crypto' ] + path_list
            return os.path.join(self.mbedtls_root, *path_list, filename)

        return os.path.join(self.mbedtls_root, *path_list, filename)

    # Utility Methods
    @staticmethod
    def parse_def_guards(def_list: Collection[str])-> str:
        """ Parse an input list of format ["HASH_DEFINE", "!HASH_DEFINE2" ] and generate a
            c compatible defined(HASH_DEFINE) && !defined(HASH_DEFINE) syntax string"""

        output = ""
        _dl = ["defined({})".format(n) if n[0] != "!" \
                     else "!defined({})".format(n[1:]) for n in def_list]
        # Split the list in chunks of 2 and add new lines
        for i in range(0, len(_dl), 2):
            output += "{} && {} && \\".format(_dl[i], _dl[i+1]) + "\n    "\
                if i+2 <= len(_dl) else _dl[i]
        return output

    @staticmethod
    def _detect_buffer_parameters(arguments: List[c_parsing_helper.ArgumentInfo],
                                  argument_names: List[str]) -> Iterator[BufferParameter]:
        """Detect function arguments that are buffers (pointer, size [,length])."""
        types = ['' if arg.suffix else arg.type for arg in arguments]
        # pairs = list of (type_of_arg_N, type_of_arg_N+1)
        # where each type_of_arg_X is the empty string if the type is an array
        # or there is no argument X.
        pairs = enumerate(itertools.zip_longest(types, types[1:], fillvalue=''))
        for i, t01 in pairs:
            if (t01[0] == 'const uint8_t *' or t01[0] == 'uint8_t *') and \
               t01[1] == 'size_t':
                yield BufferParameter(i, not t01[0].startswith('const '),
                                      argument_names[i], argument_names[i+1])

    @staticmethod
    def _parameter_should_be_copied(function_name: str,
                                    _buffer_name: Optional[str]) -> bool:
        """Whether the specified buffer argument to a PSA function should be copied.
        """
        # False-positives that do not need buffer copying
        if function_name in ('mbedtls_psa_inject_entropy',
                             'psa_crypto_driver_pake_get_password',
                             'psa_crypto_driver_pake_get_user',
                             'psa_crypto_driver_pake_get_peer'):
            return False

        return True

    # Override parent's methods
    def _write_function_call(self, out: typing_util.Writable,
                             function: c_wrapper_generator.FunctionInfo,
                             argument_names: List[str]) -> None:
        buffer_parameters = list(
            param
            for param in self._detect_buffer_parameters(function.arguments,
                                                        argument_names)
            if self._parameter_should_be_copied(function.name,
                                                function.arguments[param.index].name))

        BufferParameter.poison_multi_write(out, buffer_parameters, True)
        super()._write_function_call(out, function, argument_names)
        BufferParameter.poison_multi_write(out, buffer_parameters, False)

    def _skip_function(self, function: c_wrapper_generator.FunctionInfo) -> bool:
        if function.return_type != 'psa_status_t':
            return True
        if function.name in self._SKIP_FUNCTIONS:
            return True
        return False

    def _return_variable_name(self,
                              function: c_wrapper_generator.FunctionInfo) -> str:
        """The name of the variable that will contain the return value."""

        if function.return_type == 'psa_status_t':
            return 'status'
        return super()._return_variable_name(function)

    def _write_prologue(self, out: typing_util.Writable, header: bool) -> None:
        super()._write_prologue(out, header)

        prologue = []
        if self._CPP_GUARDS:
            prologue.append("#if {}".format(self._CPP_GUARDS))
            prologue.append('')

        for include in self._PSA_WRAPPER_INCLUDES:
            prologue.append("#include {}".format(include))

        if prologue[-1] != '':
            prologue.append('')

        out.write("\n".join(prologue))

    def _write_epilogue(self, out: typing_util.Writable, header: bool) -> None:
        if self._CPP_GUARDS:
            out.write(dedent(self.__EPILOGUE__).format(self._CPP_GUARDS))
        super()._write_epilogue(out, header)

class PSALoggingWrapper(PSAWrapper, c_wrapper_generator.Logging):
    """Generate a C source file containing wrapper functions that log PSA Crypto API calls."""

    def __init__(self,
                 stream: str,
                 output_h_f: str,
                 output_c_f: str,
                 in_headers:  Collection[str] = DEFAULTS["input_headers"],
                 config: Dict[str, Any]= DEFAULTS) -> None:

        super().__init__(output_h_f, output_c_f, in_headers, config)
        self.set_stream(stream)

    _PRINTF_TYPE_CAST = c_wrapper_generator.Logging._PRINTF_TYPE_CAST.copy()
    _PRINTF_TYPE_CAST.update({
        'mbedtls_svc_key_id_t': 'unsigned',
        'psa_algorithm_t': 'unsigned',
        'psa_drv_slot_number_t': 'unsigned long long',
        'psa_key_derivation_step_t': 'int',
        'psa_key_id_t': 'unsigned',
        'psa_key_slot_number_t': 'unsigned long long',
        'psa_key_lifetime_t': 'unsigned',
        'psa_key_type_t': 'unsigned',
        'psa_key_usage_flags_t': 'unsigned',
        'psa_pake_role_t': 'int',
        'psa_pake_step_t': 'int',
        'psa_status_t': 'int'
    })

    def _printf_parameters(self, typ: str, var: str) -> Tuple[str, List[str]]:
        if typ.startswith('const '):
            typ = typ[6:]
        if typ == 'uint8_t *':
            # Skip buffers
            return '', []
        if typ.endswith('operation_t *'):
            return '', []
        if typ in self._NOT_IMPLEMENTED:
            return '', []
        if typ == 'psa_key_attributes_t *':
            return (var + '={id=%u, lifetime=0x%08x, type=0x%08x, bits=%u, alg=%08x, usage=%08x}',
                    ['(unsigned) psa_get_key_{}({})'.format(field, var)
                     for field in ['id', 'lifetime', 'type', 'bits', 'algorithm', 'usage_flags']])
        return super()._printf_parameters(typ, var)

