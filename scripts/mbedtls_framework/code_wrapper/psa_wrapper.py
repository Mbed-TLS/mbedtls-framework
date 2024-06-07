class PSAWrapperGenerator(c_wrapper_generator.Base):
    """Generate a C source file containing wrapper functions for PSA Crypto API calls."""

    _CPP_GUARDS = ('defined(MBEDTLS_PSA_CRYPTO_C) && ' +
                   'defined(MBEDTLS_TEST_HOOKS) && \\\n    ' +
                   '!defined(RECORD_PSA_STATUS_COVERAGE_LOG)')
    _WRAPPER_NAME_PREFIX = 'mbedtls_test_wrap_'
    _WRAPPER_NAME_SUFFIX = ''

    def gather_data(self) -> None:
        """Gather PSA Crypto API function names."""
        root_dir = build_tree.guess_mbedtls_root()
        for header_name in ['crypto.h', 'crypto_extra.h']:
            # Temporary, while Mbed TLS does not just rely on the TF-PSA-Crypto
            # build system to build its crypto library. When it does, the first
            # case can just be removed.
            if os.path.isdir(os.path.join(root_dir, 'tf-psa-crypto')):
                header_path = os.path.join(root_dir, 'tf-psa-crypto',
                                           'include', 'psa', header_name)
            else:
                header_path = os.path.join(root_dir, 'include', 'psa', header_name)
            c_parsing_helper.read_function_declarations(self.functions, header_path)

    _SKIP_FUNCTIONS = frozenset([
        'mbedtls_psa_external_get_random', # not a library function
        'psa_get_key_domain_parameters', # client-side function
        'psa_get_key_slot_number', # client-side function
        'psa_key_derivation_verify_bytes', # not implemented yet
        'psa_key_derivation_verify_key', # not implemented yet
        'psa_set_key_domain_parameters', # client-side function
    ])

    def _skip_function(self, function: c_wrapper_generator.FunctionInfo) -> bool:
        if function.return_type != 'psa_status_t':
            return True
        if function.name in self._SKIP_FUNCTIONS:
            return True
        return False

    # PAKE stuff: not implemented yet
    _PAKE_STUFF = frozenset([
        'psa_crypto_driver_pake_inputs_t *',
        'psa_pake_cipher_suite_t *',
    ])

    def _return_variable_name(self,
                              function: c_wrapper_generator.FunctionInfo) -> str:
        """The name of the variable that will contain the return value."""
        if function.return_type == 'psa_status_t':
            return 'status'
        return super()._return_variable_name(function)

    _FUNCTION_GUARDS = c_wrapper_generator.Base._FUNCTION_GUARDS.copy() \
        #pylint: disable=protected-access
    _FUNCTION_GUARDS.update({
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
    })

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
    def _write_poison_buffer_parameter(out: typing_util.Writable,
                                       param: BufferParameter,
                                       poison: bool) -> None:
        """Write poisoning or unpoisoning code for a buffer parameter.
        Write poisoning code if poison is true, unpoisoning code otherwise.
        """
        out.write('    MBEDTLS_TEST_MEMORY_{}({}, {});\n'.format(
            'POISON' if poison else 'UNPOISON',
            param.buffer_name, param.size_name
        ))

    def _write_poison_buffer_parameters(self, out: typing_util.Writable,
                                        buffer_parameters: List[BufferParameter],
                                        poison: bool) -> None:
        """Write poisoning or unpoisoning code for the buffer parameters.
        Write poisoning code if poison is true, unpoisoning code otherwise.
        """
        if not buffer_parameters:
            return
        out.write('#if !defined(MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)\n')
        for param in buffer_parameters:
            self._write_poison_buffer_parameter(out, param, poison)
        out.write('#endif /* !defined(MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS) */\n')

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

    def _write_function_call(self, out: typing_util.Writable,
                             function: c_wrapper_generator.FunctionInfo,
                             argument_names: List[str]) -> None:
        buffer_parameters = list(
            param
            for param in self._detect_buffer_parameters(function.arguments,
                                                        argument_names)
            if self._parameter_should_be_copied(function.name,
                                                function.arguments[param.index].name))
        self._write_poison_buffer_parameters(out, buffer_parameters, True)
        super()._write_function_call(out, function, argument_names)
        self._write_poison_buffer_parameters(out, buffer_parameters, False)

    def _write_prologue(self, out: typing_util.Writable, header: bool) -> None:
        super()._write_prologue(out, header)
        out.write("""
#if {}
#include <psa/crypto.h>
#include <test/memory.h>
#include <test/psa_crypto_helpers.h>
#include <test/psa_test_wrappers.h>
"""
                  .format(self._CPP_GUARDS))

    def _write_epilogue(self, out: typing_util.Writable, header: bool) -> None:
        out.write("""
#endif /* {} */
"""
                  .format(self._CPP_GUARDS))
        super()._write_epilogue(out, header)


class PSALoggingWrapperGenerator(PSAWrapperGenerator, c_wrapper_generator.Logging):
    """Generate a C source file containing wrapper functions that log PSA Crypto API calls."""

    def __init__(self, stream: str) -> None:
        super().__init__()
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
        'psa_status_t': 'int',
    })

    def _printf_parameters(self, typ: str, var: str) -> Tuple[str, List[str]]:
        if typ.startswith('const '):
            typ = typ[6:]
        if typ == 'uint8_t *':
            # Skip buffers
            return '', []
        if typ.endswith('operation_t *'):
            return '', []
        if typ in self._PAKE_STUFF:
            return '', []
        if typ == 'psa_key_attributes_t *':
            return (var + '={id=%u, lifetime=0x%08x, type=0x%08x, bits=%u, alg=%08x, usage=%08x}',
                    ['(unsigned) psa_get_key_{}({})'.format(field, var)
                     for field in ['id', 'lifetime', 'type', 'bits', 'algorithm', 'usage_flags']])
        return super()._printf_parameters(typ, var)