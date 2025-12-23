"""Information about configuration macros and derived macros."""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import glob
import os
import re
from typing import FrozenSet, Iterable, Iterator

from . import build_tree


class ConfigMacros:
    """Information about configuration macros and derived macros."""

    def __init__(self, public: FrozenSet[str], adjusted: FrozenSet[str]) -> None:
        self._public = public
        self._internal = adjusted - public

    def options(self) -> FrozenSet[str]:
        """The set of configuration options in this product."""
        return self._public

    def internal(self) -> FrozenSet[str]:
        """The set of internal option-like macros in this product."""
        return self._internal


class Current(ConfigMacros):
    """Information about config-like macros parsed from the source code."""

    _PUBLIC_CONFIG_HEADERS = [
        'include/mbedtls/mbedtls_config.h',
        'include/psa/crypto_config.h',
    ]

    _ADJUST_CONFIG_HEADERS = [
        'include/**/*adjust*.h',
        'drivers/*/include/**/*adjust*.h',
    ]

    _DEFINE_RE = re.compile(r'[/ ]*# *define  *([A-Z_a-z][0-9A-Z_a-z]*)')

    def _list_files(self, patterns: Iterable[str]) -> Iterator[str]:
        """Yield files matching the given glob patterns."""
        for pattern in patterns:
            yield from glob.glob(os.path.join(self._root, self._submodule,
                                              pattern),
                                 recursive=True)

    def _search_file(self, filename: str) -> Iterator[str]:
        """Yield macros defined in the given file."""
        with open(filename, encoding='utf-8') as input_:
            for line in input_:
                m = self._DEFINE_RE.match(line)
                if m:
                    yield m.group(1)

    def _search_files(self, patterns: Iterable[str]) -> FrozenSet[str]:
        """Yield macros defined in files matching the given glob patterns."""
        return frozenset(element
                         for filename in self._list_files(patterns)
                         for element in self._search_file(filename))

    def __init__(self, submodule: str = '') -> None:
        """Look for macros defined in the given submodule's source tree.

        If submodule is omitted or empty, look in the root module.
        """
        self._root = build_tree.guess_project_root()
        self._submodule = submodule
        public = self._search_files(self._PUBLIC_CONFIG_HEADERS)
        adjusted = self._search_files(self._ADJUST_CONFIG_HEADERS)
        super().__init__(public, adjusted)


class History(ConfigMacros):
    """Information about config-like macros in a previous version.

    Load files created by ``framework/scripts/save_config_history.sh``.
    """

    def _load_file(self, basename: str) -> FrozenSet[str]:
        """Load macro names from the given file in the history directory."""
        filename = os.path.join(self._history_dir, basename)
        with open(filename, encoding='ascii') as input_:
            return frozenset(line.strip()
                             for line in input_)

    def __init__(self, project: str, version: str) -> None:
        """Read information about the given project at the given version.

        The information must be present in history files in the framework.
        """
        self._history_dir = os.path.join(build_tree.framework_root(), 'history')
        public = self._load_file(f'config-options-{project}-{version}.txt')
        adjusted = self._load_file(f'config-adjust-{project}-{version}.txt')
        super().__init__(public, adjusted)
