#!/usr/bin/env python3

"""
Generate miscellaneous TLS test cases relating to the handshake.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
import sys
from typing import Optional

from mbedtls_framework import tls_test_case
from mbedtls_framework import typing_util

from mbedtls_framework.tls_test_case import Side, Version


# Assume that a TLS 1.2 ClientHello used in these tests will be at most
# this many bytes long.
TLS12_CLIENT_HELLO_ASSUMED_MAX_LENGTH = 255

# Minimum handshake fragment length that Mbed TLS supports.
TLS_HANDSHAKE_FRAGMENT_MIN_LENGTH = 4

def write_tls_handshake_defragmentation_test(
        out: typing_util.Writable,
        side: Side,
        length: Optional[int],
        version: Optional[Version] = None
) -> None:
    """Generate one TLS handshake defragmentation test.

    :param out: file to write to.
    :param side: which side is Mbed TLS.
    :param length: fragment length, or None to not fragment.
    :param version: protocol version, if forced.
    """
    #pylint: disable=chained-comparison,too-many-branches,too-many-statements

    our_args = ''
    their_args = ''

    if length is None:
        description = 'no fragmentation, for reference'
    else:
        description = 'len=' + str(length)
    if version is not None:
        description += ', TLS 1.' + str(version.value)
    description = f'Handshake defragmentation on {side.name.lower()}: {description}'
    tc = tls_test_case.TestCase(description)

    if version == Version.TLS12 and \
       length is not None and \
       length >= TLS_HANDSHAKE_FRAGMENT_MIN_LENGTH and \
       length < 16 and \
       side == side.CLIENT:
        # Skip test cases where the Finished message is fragmented in TLS 1.2.
        # This is currently buggy when the symmetric encryption used an
        # explicit IV (CBC, GCM or CCM; Chachapoly and null work, as does
        # TLS 1.3, because they use a purely implicit IV).
        tc.requirements.append('skip_next_test')

    if version is not None:
        their_args += ' ' + version.openssl_option()
        # Emit a version requirement, because we're forcing the version via
        # OpenSSL, not via Mbed TLS, and the automatic depdendencies in
        # ssl-opt.sh only handle forcing the version via Mbed TLS.
        tc.requirements.append(version.requires_command())
        if side == Side.SERVER and version == Version.TLS12 and \
           length is not None and \
           length <= TLS12_CLIENT_HELLO_ASSUMED_MAX_LENGTH:
            # Server-side ClientHello defragmentation is only supported in
            # the TLS 1.3 message parser. When that parser sees an 1.2-only
            # ClientHello, it forwards the reassembled record to the
            # TLS 1.2 ClientHello parser so the ClientHello can be fragmented.
            # When TLS 1.3 support is disabled in the server (at compile-time
            # or at runtime), the TLS 1.2 ClientHello parser only sees
            # the first fragment of the ClientHello.
            tc.requirements.append('requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3')
            tc.description += '  TLS 1.3 ClientHello -> 1.2 Handshake'

    # To guarantee that the handhake messages are large enough and need to be
    # split into fragments, the tests require certificate authentication.
    # The party in control of the fragmentation operations is OpenSSL and
    # will always use server5.crt (548 Bytes).
    if length is not None and \
       length >= TLS_HANDSHAKE_FRAGMENT_MIN_LENGTH:
        tc.requirements.append('requires_certificate_authentication')
        if version == Version.TLS12 and side == Side.CLIENT:
            #The server uses an ECDSA cert, so make sure we have a compatible key exchange
            tc.requirements.append(
                'requires_config_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED')
    else:
        # This test case may run in a pure-PSK configuration. OpenSSL doesn't
        # allow this by default with TLS 1.3.
        their_args += ' -allow_no_dhe_kex'

    if length is None:
        forbidden_patterns = [
            'reassembled record',
            'waiting for more fragments',
        ]
        wanted_patterns = []
    elif length < TLS_HANDSHAKE_FRAGMENT_MIN_LENGTH:
        their_args += ' -split_send_frag ' + str(length)
        tc.exit_code = 1
        forbidden_patterns = []
        wanted_patterns = [
            'handshake message too short: ' + str(length),
            'SSL - An invalid SSL record was received',
        ]
        if side == Side.SERVER:
            wanted_patterns[0:0] = ['<= parse client hello']
        elif version == Version.TLS13:
            wanted_patterns[0:0] = ['=> ssl_tls13_process_server_hello']
    else:
        their_args += ' -split_send_frag ' + str(length)
        forbidden_patterns = []
        wanted_patterns = [
            'reassembled record',
            fr'handshake fragment: 0 \.\. {length} of [0-9]\+ msglen {length}',
            fr'waiting for more fragments ({length} of',
        ]

    if side == Side.CLIENT:
        tc.client = '$P_CLI debug_level=4' + our_args
        tc.server = '$O_NEXT_SRV' + their_args
        tc.wanted_client_patterns = wanted_patterns
        tc.forbidden_client_patterns = forbidden_patterns
    else:
        their_args += ' -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key'
        our_args += ' auth_mode=required'
        tc.client = '$O_NEXT_CLI' + their_args
        tc.server = '$P_SRV debug_level=4' + our_args
        tc.wanted_server_patterns = wanted_patterns
        tc.forbidden_server_patterns = forbidden_patterns
    tc.write(out)

def write_tls_handshake_defragmentation_tests(out: typing_util.Writable) -> None:
    """Generate TLS handshake defragmentation tests."""
    for side in Side.CLIENT, Side.SERVER:
        write_tls_handshake_defragmentation_test(out, side, None)
        for length in [512, 513, 256, 128, 64, 36, 32, 16, 13, 5, 4, 3]:
            write_tls_handshake_defragmentation_test(out, side, length, Version.TLS13)
            write_tls_handshake_defragmentation_test(out, side, length, Version.TLS12)


def write_handshake_tests(out: typing_util.Writable) -> None:
    """Generate handshake tests."""
    out.write(f"""\
# Miscellaneous tests related to the TLS handshake layer.
#
# Automatically generated by {os.path.basename(sys.argv[0])}. Do not edit!

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

""")
    write_tls_handshake_defragmentation_tests(out)
    out.write("""\
# End of automatically generated file.
""")

def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',
                        default='tests/opt-testcases/handshake-generated.sh',
                        help='Output file')
    args = parser.parse_args()
    with open(args.output, 'w') as out:
        write_handshake_tests(out)

if __name__ == '__main__':
    main()
