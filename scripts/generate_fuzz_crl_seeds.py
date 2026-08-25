#!/usr/bin/env python3
"""Generate hand-built X.509 CRL fuzzing seeds.

These CRLs target cases that the existing corpus does not cover and that cannot be
(easily) generated using the openssl CLI.

There are two CRLs:

    --entry-ext-output [path]
        a v2 CRL whose single revoked entry carries a CRLReason entry extension
    --no-nextupdate-output [path]
        a v1 CRL with no nextUpdate field and a revoked entry with no entry extensions

Output is PEM. The step that NUL-terminates PEM certificates should include these, so
that the PEM decoder is exercised by the fuzzer.
"""

import argparse
import base64


def der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = b""
    while length:
        body = bytes([length & 0xFF]) + body
        length >>= 8
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def der_oid(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    body = [40 * parts[0] + parts[1]]
    for node in parts[2:]:
        if node < 0x80:
            body.append(node)
        else:
            chunk = []
            while node:
                chunk.insert(0, node & 0x7F)
                node >>= 7
            for i in range(len(chunk) - 1):
                chunk[i] |= 0x80
            body += chunk
    return tlv(0x06, bytes(body))


# Reusable DER fragments.
SHA256_RSA = tlv(0x30, der_oid("1.2.840.113549.1.1.11") + tlv(0x05, b""))
ISSUER = tlv(0x30, tlv(0x31, tlv(0x30, der_oid("2.5.4.3") + tlv(0x13, b"Fuzz CRL CA"))))
DUMMY_SIGNATURE = tlv(0x03, b"\x00\xde\xad\xbe\xef")


def utc_time(value: bytes) -> bytes:
    return tlv(0x17, value)


def crl_reason(reason: int) -> bytes:
    """A single CRLReason (2.5.29.21) entry extension carrying an ENUMERATED."""
    extn_value = tlv(0x0A, bytes([reason]))  # ENUMERATED
    extension = tlv(0x30, der_oid("2.5.29.21") + tlv(0x04, extn_value))
    return tlv(0x30, extension)  # Extensions ::= SEQUENCE OF


def certificate_list(tbs: bytes) -> bytes:
    return tlv(0x30, tbs + SHA256_RSA + DUMMY_SIGNATURE)


def crl_with_entry_extension() -> bytes:
    """v2 CRL with one revoked entry carrying a CRLReason entry extension."""
    entry = tlv(
        0x30,
        tlv(0x02, b"\x10\x01")  # serial
        + utc_time(b"260527000000Z")  # revocationDate
        + crl_reason(1),  # keyCompromise
    )
    tbs = tlv(
        0x30,
        tlv(0x02, b"\x01")  # version v2 (1)
        + SHA256_RSA
        + ISSUER
        + utc_time(b"260527000000Z")  # thisUpdate
        + utc_time(b"270527000000Z")  # nextUpdate
        + tlv(0x30, entry),  # revokedCertificates
    )
    return certificate_list(tbs)


def crl_without_nextupdate() -> bytes:
    """v1 CRL with no nextUpdate, one revoked entry with no entry extensions."""
    entry = tlv(0x30, tlv(0x02, b"\x10\x01") + utc_time(b"260527000000Z"))
    tbs = tlv(
        0x30,
        SHA256_RSA  # no version (v1)
        + ISSUER
        + utc_time(b"260527000000Z")  # thisUpdate, no nextUpdate
        + tlv(0x30, entry),  # revokedCertificates
    )
    return certificate_list(tbs)


def write_pem(path: str, der: bytes) -> None:
    encoded = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    pem = "-----BEGIN X509 CRL-----\n" + "\n".join(lines) + "\n-----END X509 CRL-----\n"
    with open(path, "w") as fp:
        fp.write(pem)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--entry-ext-output",
        required=True,
        help="path for the entry-extension CRL seed",
    )
    parser.add_argument(
        "--no-nextupdate-output",
        required=True,
        help="path for the no-nextUpdate CRL seed",
    )
    args = parser.parse_args()

    write_pem(args.entry_ext_output, crl_with_entry_extension())
    write_pem(args.no_nextupdate_output, crl_without_nextupdate())


if __name__ == "__main__":
    main()
