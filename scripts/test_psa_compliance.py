#!/usr/bin/env python3
"""Run the PSA Crypto API compliance test suite.

Transitional wrapper to facilitate the migration of consuming branches.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

from mbedtls_framework import psa_compliance

if __name__ == '__main__':
    psa_compliance.main()
