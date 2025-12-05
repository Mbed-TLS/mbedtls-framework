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
from typing import Iterable, List, Match, Optional, Set

def get_parsearg_base() -> argparse.ArgumentParser:
    """ Get base arguments for scripts building a TF-PSA-Crypto test driver """
    parser = argparse.ArgumentParser(description="""\
        Clone the built-in driver tree, rewrite header inclusions and prefix
        exposed C identifiers.
        """)

    parser.add_argument("dst_dir", metavar="DST_DIR",
                        help="Destination directory (relative to repository root)")
    parser.add_argument("--driver", default="libtestdriver1", metavar="DRIVER",
                        help="Test driver name (default: %(default)s).")
    parser.add_argument('--list-vars-for-cmake', nargs="?", \
                        const="__AUTO__", metavar="FILE",
                        help="""
        Generate a file to be included from a CMakeLists.txt and exit. The file
        defines CMake list variables with the script's inputs/outputs files. If
        FILE is omitted, the output name defaults to '<DRIVER>-list-vars.cmake'.
        """)
    return parser

class TestDriverGenerator:
    """A TF-PSA-Crypto test driver generator"""
    def __init__(self, src_dir: Path, dst_dir: Path, driver: str, \
                 exclude_files: Optional[Iterable[str]] = None) -> None:
        """
        Initialize a test driver generator.

        Args:
            src_dir (Path):
                Path to the source directory that contains the built-in driver.
                If this path is relative, it should be relative to the repository
                root so that the source paths returned by `write_list_vars_for_cmake`
                are correct.

                The source directory is expected to contain:
                - an `include` directory
                - an `src` directory
                - the `include/` directory contains exactly one subdirectory

            dst_dir (Path):
                Path to the destination directory where the rewritten tree will
                be created.

            driver (str):
                Name of the driver. This is used as a prefix when rewritting
                the tree.

            exclude_files (Optional[Set[str]]):
                Glob patterns for the basename of the files to be excluded from
                the source directory.
        """
        self.src_dir = src_dir
        self.dst_dir = dst_dir
        self.driver = driver
        self.exclude_files: Iterable[str] = ()
        if exclude_files is not None:
            self.exclude_files = exclude_files

        if not (src_dir / "include").is_dir():
            raise RuntimeError(f'"include" directory in {src_dir} not found')

        if not (src_dir / "src").is_dir():
            raise RuntimeError(f'"src" directory in {src_dir} not found')

    def write_list_vars_for_cmake(self, fname: str) -> None:
        src_relpaths = self.__get_src_code_files()
        with open(self.dst_dir / fname, "w") as f:
            f.write(f"set({self.driver}_input_files " + \
                     "\n".join(str(path) for path in src_relpaths) + ")\n\n")
            f.write(f"set({self.driver}_files " + \
                    "\n".join(str(self.__get_dst_relpath(path.relative_to(self.src_dir))) \
                     for path in src_relpaths) + ")\n\n")
            f.write(f"set({self.driver}_src_files " + \
                    "\n".join(str(path.relative_to(self.src_dir)) \
                    for path in src_relpaths if path.suffix == ".c") + ")\n")


    def get_identifiers_to_prefix(self, prefixes: Set[str]) -> Set[str]:
        """
        Get the set of identifiers that will be prefixed in the test driver code.

        This method is intended to be amended by subclasses in consuming branches.

        The default implementation returns the complete set of identifiers from
        the built-in driver whose names begin with any of the `prefixes`. These
        are the identifiers that could be renamed in the test driver before
        adaptation.

        Subclasses need to filter, transform, or otherwise adjust the set of
        identifiers that should be renamed when generating the test driver.

        Args:
             prefixes (Set[str]):
                 The set of identifier prefixes used by the built-in driver
                 for the symbols it exposes to the other parts of the crypto
                 library. All identifiers beginning with any of these
                 prefixes are candidates for renaming in the test driver to
                 avoid symbol clashes.

        Returns:
            Set[str]: The default set of identifiers to rename.
        """
        identifiers = set()
        for file in self.__get_code_files(self.dst_dir):
            identifiers.update(self.get_c_identifiers(file))

        identifiers_with_prefixes = set()
        for identifier in identifiers:
            if any(identifier.startswith(prefix) for prefix in prefixes):
                identifiers_with_prefixes.add(identifier)
        return identifiers_with_prefixes

    def create_test_driver_tree(self, prefixes: Set[str]) -> None:
        """
        Build a test driver tree from `self.src_dir` into `self.dst_dir`.

        Only the `include/` and `src/` subdirectories of the source tree are
        used, and their internal directory structure is preserved.

        Only "*.h" and "*.c" files are copied. Files whose basenames match any
        of the glob patterns in `self.exclude_files` are excluded.

        Inside the destination tree, the single subdirectory of `include/`
        is renamed to `self.driver`, and any header inclusions referencing it are
        rewritten accordingly.

        Symbol identifiers exposed by the built-in driver are renamed by
        prefixing them with `{self.driver}_` to avoid collisions when linking the
        built-in driver and the test driver together in the crypto library.

        Args:
             prefixes (Set[str]):
                 The set of identifier prefixes used by the built-in driver
                 for the symbols it exposes to the other parts of the crypto
                 library. All identifiers beginning with any of these
                 prefixes are candidates for renaming in the test driver to
                 avoid symbol clashes.
        """
        include = self.src_dir / "include"
        entries = list(include.iterdir())
        if len(entries) != 1 or not entries[0].is_dir():
            raise RuntimeError(f"Found more than one directory in {include}")

        src_include_dir_name = entries[0].name

        if (self.dst_dir / "include").exists():
            shutil.rmtree(self.dst_dir / "include")

        if (self.dst_dir / "src").exists():
            shutil.rmtree(self.dst_dir / "src")

        # Clone the source tree into `dst_dir`
        for file in self.__get_src_code_files():
            dst = self.dst_dir / \
                  self.__get_dst_relpath(file.relative_to(self.src_dir))
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, dst)

        # Modify the test driver files
        test_driver_include_dir = self.dst_dir / "include" / self.driver
        headers = {
            f.relative_to(test_driver_include_dir).as_posix() \
            for f in test_driver_include_dir.rglob("*.h")
        }
        identifiers_to_prefix = self.get_identifiers_to_prefix(prefixes)

        for f in self.__get_code_files(self.dst_dir):
            self.__rewrite_test_driver_file(f, headers,\
                                            src_include_dir_name,
                                            identifiers_to_prefix, self.driver)

    @staticmethod
    def __get_code_files(root: Path) -> List[Path]:
        """
        Return all "*.c" and "*.h" files found recursively under the
        `include` and `src` subdirectories of `root`.
        """
        return sorted(path
                      for directory in ('include', 'src')
                      for path in (root / directory).rglob('*.[hc]'))

    def __get_src_code_files(self) -> List[Path]:
        """
        Return all "*.c" and "*.h" files found recursively under the
        `include` and `src` subdirectories of the source directory `self.src_dir`
        excluding the files whose basename match any of the patterns in
        `self.exclude_files`.
        """
        out = []
        for file in self.__get_code_files(self.src_dir):
            if not any(fnmatch(file.name, pattern) for pattern in self.exclude_files):
                out.append(file)
        return out

    def __get_dst_relpath(self, src_relpath: Path) -> Path:
        """
        Return the path relative to `dst_dir` of the file that corresponds to the
        file with relative path `src_relpath` in the source tree.

        The path is the same as `src_relpath`, except that occurrences of
        `include/mbedtls/...` are replaced with `include/driver/...`.

        """
        assert not src_relpath.is_absolute(), "src_relpath must be relative"

        parts = src_relpath.parts
        if len(parts) > 2 and parts[0] == "include" and parts[1] == "mbedtls":
            return Path("include", self.driver, *parts[2:])

        return src_relpath

    @staticmethod
    def get_c_identifiers(file: Path) -> Set[str]:
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

        This method requires `Universal Ctags`. The command used here has been
        validated with Universal Ctags 5.9.0 (the default `ctags` on Ubuntu
        22.04 and 24.04). `Exuberant Ctags` is not compatible: it does not
        support all `--c-kinds` flags used here, and will either fail with an
        error or produce incomplete results.
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

    @staticmethod
    def __rewrite_test_driver_file(file: Path, headers: Set[str],
                                   src_include_dir: str,
                                   identifiers_to_prefix: Set[str],
                                   driver: str) -> None:
        """
        Rewrite a test driver file:
        1) Rewrite `#include` directives in `file` that refer to `src_include_dir/...`
           so that they instead refer to `driver/...`.

           For example:
              #include "mbedtls/private/aes.h"
           becomes:
               #include "libtestdriver1/private/aes.h"
        2) Prefix each identifier in `identifiers` with the uppercase
           form of `driver` if the identifier is uppercase, or with the lowercase
           form of `driver` otherwise.
        """
        text = file.read_text(encoding="utf-8")

        include_line_re = re.compile(
            fr'^\s*#\s*include\s*([<"]){src_include_dir}/([^>"]+)([>"])',
            re.MULTILINE
        )
        def repl_header_inclusion(m: Match) -> str:
            header = m.group(2)
            if header in headers:
                return f'#include {m.group(1)}{driver}/{header}{m.group(3)}'
            return m.group(0)
        intermediate_text = include_line_re.sub(repl_header_inclusion, text)

        c_identifier_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
        prefix_uppercased = driver.upper()
        prefix_lowercased = driver.lower()

        def repl(m: Match) -> str:
            identifier = m.group(0)
            if identifier in identifiers_to_prefix:
                if identifier[0].isupper():
                    return f"{prefix_uppercased}_{identifier}"
                else:
                    return f"{prefix_lowercased}_{identifier}"
            return identifier

        new_text = c_identifier_re.sub(repl, intermediate_text)
        file.write_text(new_text, encoding="utf-8")
