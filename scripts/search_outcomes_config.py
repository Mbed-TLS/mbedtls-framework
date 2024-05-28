#!/usr/bin/env python
"""Search an outcome file for configurations with given settings.

Read an outcome file and report the configurations in which test_suite_config
runs with the required settings (compilation option enabled or disabled).
"""

import argparse
import os
import re
import subprocess
from typing import Dict, FrozenSet, Iterator, List, Set


def make_regexp_for_settings(settings: List[str]) -> str:
    """Construct a regexp matching the interesting outcome lines.

    Interesting outcome lines are from test_suite_config where the given
    setting is passing.

    We assume that the elements of settings don't contain regexp special
    characters.
    """
    return (r';test_suite_config[^;]*;Config: (' +
            '|'.join(settings) +
            r');PASS;')

def run_grep(regexp: str, outcome_file: str) -> List[str]:
    """Run grep on the outcome file and return the matching lines."""
    env = os.environ.copy()
    env['LC_ALL'] = 'C' # Speeds up some versions of GNU grep
    try:
        return subprocess.check_output(['grep', '-E', regexp, outcome_file],
                                       encoding='ascii',
                                       env=env).splitlines()
    except subprocess.CalledProcessError as exn:
        if exn.returncode == 1:
            return [] # No results. We don't consider this an error.
        raise

OUTCOME_LINE_RE = re.compile(r'[^;]*;'
                             r'([^;]*);'
                             r'test_suite_config\.(?:[^;]*);'
                             r'Config: ([^;]*);'
                             r'PASS;')

def extract_configuration_data(outcome_lines: List[str]) -> Dict[str, FrozenSet[str]]:
    """Extract the configuration data from outcome lines.

    The result maps a configuration name to the list of passing settings
    in that configuration.
    """
    config_data = {} #type: Dict[str, Set[str]]
    for line in outcome_lines:
        m = OUTCOME_LINE_RE.match(line)
        # make_regexp_for_settings() arranges to only return lines that
        # should match here.
        assert m is not None
        config_name, setting = m.groups()
        if config_name not in config_data:
            config_data[config_name] = set()
        config_data[config_name].add(setting)
    return dict((name, frozenset(settings))
                for name, settings in config_data.items())


def matching_configurations(config_data: Dict[str, FrozenSet[str]],
                            required: List[str]) -> Iterator[str]:
    """Search configurations with the given passing settings.

    config_data maps a configuration name to the list of passing settings
    in that configuration.

    Each setting should be an Mbed TLS compile setting (MBEDTLS_xxx or
    PSA_xxx), optionally prefixed with "!".
    """
    required_set = frozenset(required)
    for config, observed in config_data.items():
        if required_set.issubset(observed):
            yield config

def search_config_outcomes(outcome_file: str, settings: List[str]) -> List[str]:
    """Search the given outcome file for reports of the given settings.

    Each setting should be an Mbed TLS compile setting (MBEDTLS_xxx or
    PSA_xxx), optionally prefixed with "!".
    """
    # The outcome file is large enough (hundreds of MB) that parsing it
    # in Python is slow. Use grep to speed this up considerably.
    regexp = make_regexp_for_settings(settings)
    outcome_lines = run_grep(regexp, outcome_file)
    config_data = extract_configuration_data(outcome_lines)
    return sorted(matching_configurations(config_data, settings))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outcome-file', '-f', metavar='FILE',
                        default='outcomes.csv',
                        help='Outcome file to read (default: outcomes.csv)')
    parser.add_argument('settings', metavar='SETTING', nargs='+',
                        help='Required setting (e.g. "MBEDTLS_RSA_C" or "!PSA_WANT_ALG_SHA256")')
    options = parser.parse_args()
    found = search_config_outcomes(options.outcome_file, options.settings)
    for name in found:
        print(name)

if __name__ == '__main__':
    main()
