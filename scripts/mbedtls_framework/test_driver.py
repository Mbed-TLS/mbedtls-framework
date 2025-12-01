"""Library for building a TF-PSA-Crypto test driver from the built-in driver
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import argparse
import re
import shutil
import subprocess

from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Match, Optional, Set

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

def iter_code_files(root: Path) -> Iterable[Path]:
    """
    Iterate over all "*.c" and "*.h" files found recursively under the `include`
    and `src` subdirectories of `root`.
    """
    for directory in ("include", "src"):
        directory_path = root / directory
        for ext in (".c", ".h"):
            yield from directory_path.rglob(f"*{ext}")

def run_ctags(file: Path) -> Set[str]:
    """
    Extract the C identifiers in `file` using ctags.

    Identifiers of the following types are returned (with their corresponding
    ctags c-kinds flag in parentheses):

    - macro definitions (d)
    - enum values (e)
    - functions (f)
    - enum tags (g)
    - function prototypes (p)
    - struct tags (s)
    - typedefs (t)
    - union tags (u)
    - global variables (v)
    """

    result = subprocess.run(
        ["ctags", "-x", "--language-force=C", "--c-kinds=defgpstuv", str(file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        check=True
    )
    identifiers = set()
    for line in result.stdout.splitlines():
        identifiers.add(line.split()[0])

    return identifiers

class TestDriverGenerator:
    """A TF-PSA-Crypto test driver generator"""
    def __init__(self, dst_dir: Path, driver: str):
        self.dst_dir = dst_dir
        self.driver = driver
        # Path of 'dst_dir'/include/'driver'
        self.test_driver_include_dir = None #type: Path | None

    def build_tree(self, src_dir: Path, exclude_files: Optional[Set[str]] = None) -> None:
        """
        Build a test driver tree from `src_dir`.

        The source directory `src_dir` is expected to have the following structure:
        - an `include` directory
        - an `src` directory
        - the `include` directory contains exactly one subdirectory

        Only the `include` and `src` directories from `src_dir` are used to build
        the test driver tree, and their directory structure is preserved.

        Only "*.h" and "*.c" files are copied. Files whose names match any of the
        patterns in `exclude_files` are excluded.

        The subdirectory inside `include` is renamed to `driver` in the test driver
        tree, and header inclusions are adjusted accordingly.
        """
        include = src_dir / "include"
        if not include.is_dir():
            raise RuntimeError(f'Do not find "include" directory in {src_dir}')

        src = src_dir / "src"
        if not src.is_dir():
            raise RuntimeError(f'Do not find "src" directory in {src_dir}')

        entries = list(include.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise RuntimeError(f"Found more than one directory in {include}")

        src_include_dir_name = entries[0].name

        if (self.dst_dir / "include").exists():
            shutil.rmtree(self.dst_dir / "include")

        if (self.dst_dir / "src").exists():
            shutil.rmtree(self.dst_dir / "src")

        if exclude_files is None:
            exclude_files = set()

        for file in iter_code_files(src_dir):
            if any(fnmatch(file.name, pattern) for pattern in exclude_files):
                continue
            dst = self.dst_dir / file.relative_to(src_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, dst)

        self.test_driver_include_dir = self.dst_dir / "include" / self.driver
        (self.dst_dir / "include" / src_include_dir_name).rename( \
             self.test_driver_include_dir)

        headers = {
            f.relative_to(self.test_driver_include_dir).as_posix() \
            for f in self.test_driver_include_dir.rglob("*.h")
        }
        for f in iter_code_files(self.dst_dir):
            self.__rewrite_inclusions_in_file(f, headers, \
                                              src_include_dir_name, self.driver)

    def get_identifiers_with_prefixes(self, prefixes: Set[str]):
        """
        Return the identifiers in the test driver that start with any of the given
        prefixes.

        All exposed identifiers are expected to start with one of these prefixes.
        The returned set is therefore a superset of the exposed identifiers that
        need to be prefixed.
        """
        identifiers = set()
        for file in iter_code_files(self.dst_dir):
            identifiers.update(run_ctags(file))

        identifiers_with_prefixes = set()
        for identifier in identifiers:
            if any(identifier.startswith(prefix) for prefix in prefixes):
                identifiers_with_prefixes.add(identifier)
        return identifiers_with_prefixes

    def prefix_identifiers(self, identifiers_to_prefix: Set[str]):
        """
        In all test driver files, prefix each identifier in `identifiers_to_prefix`
        with the test driver prefix: <DRIVER>_ for uppercase identifiers,
        and <driver>_ for lowercase ones.
        """
        for f in iter_code_files(self.dst_dir):
            self.__prefix_identifiers_in_file(f, identifiers_to_prefix, self.driver)

    @staticmethod
    def __rewrite_inclusions_in_file(file: Path, headers: Set[str],
                                     src_include_dir: str, driver: str,) -> None:
        """
        Rewrite `#include` directives in `file` that refer to `src_include_dir/...`
        so that they instead refer to `driver/...`.

        For example:
            #include "mbedtls/private/aes.h"
        becomes:
            #include "libtestdriver1/private/aes.h"
        """
        include_line_re = re.compile(
            fr'^\s*#\s*include\s*([<"])\s*{src_include_dir}/([^>"]+)\s*([>"])',
            re.MULTILINE
        )
        text = file.read_text(encoding="utf-8")
        changed = False

        def repl(m: Match) -> str:
            nonlocal changed
            header = m.group(2)
            if header in headers:
                changed = True
                return f'#include {m.group(1)}{driver}/{header}{m.group(3)}'
            return m.group(0)

        new_text = include_line_re.sub(repl, text)
        if changed:
            file.write_text(new_text, encoding="utf-8")

    @staticmethod
    def __prefix_identifiers_in_file(file: Path, identifiers: Set[str], \
                                     prefix: str) -> None:
        """
        In `file`, prefix each identifier in `identifiers` with the uppercase
        form of `prefix` if the identifier is uppercase, or with the lowercase
        form of `prefix` otherwise.
        """
        c_identifier_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
        text = file.read_text(encoding="utf-8")
        prefix_uppercased = prefix.upper()
        prefix_lowercased = prefix.lower()

        def repl(m: Match) -> str:
            identifier = m.group(0)
            if identifier in identifiers:
                if identifier[0].isupper():
                    return f"{prefix_uppercased}_{identifier}"
                else:
                    return f"{prefix_lowercased}_{identifier}"
            return identifier

        new_text = c_identifier_re.sub(repl, text)
        file.write_text(new_text, encoding="utf-8")
