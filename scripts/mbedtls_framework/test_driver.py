"""Library for building a TF-PSA-Crypto test driver from the built-in driver
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import argparse

from pathlib import Path

def get_parsearg_base() -> argparse.ArgumentParser:
    """ Get base arguments for scripts building a TF-PSA-Crypto test driver """
    parser = argparse.ArgumentParser(description= \
        "Clone partially builtin tree, rewrite header inclusions and prefix"
        "exposed C identifiers.")

    parser.add_argument("dst_dir", metavar="DST_DIR",
                        help="Destination directory.\n"
                        " - If absolute, used as-is.\n"
                        " - If relative, interpreted relative to the repository root.\n")
    parser.add_argument("--driver", default="libtestdriver1", metavar="DRIVER",
                        help="Test driver name (default: %(default)s).")
    return parser

class TestDriverGenerator:
    """A TF-PSA-Crypto test driver generator"""
    def __init__(self, dst_dir: Path, driver: str):
        self.dst_dir = dst_dir
        self.driver = driver
        # Path of 'dst_dir'/include/'driver'
        self.test_driver_include_dir = None #type: Path | None
