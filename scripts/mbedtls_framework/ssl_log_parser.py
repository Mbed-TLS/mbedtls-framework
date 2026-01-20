"""Parse logs from ssl_client2 and ssl_server2."""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import re
from typing import Dict, Iterator, List, Tuple


class Info:
    """Information gathered from a log of ssl_client2 or ssl_server2."""

    DUMPING_RE = re.compile(' +'.join([
        r'(?P<filename>\S+):(?P<lineno>[0-9]+):',
        r'\|(?P<level>[0-9]+)\|(?: (?P<address>\w+):)?',
        r'dumping \'(?P<what>.*?)\'',
        r'\((?P<length>[0-9]+) bytes\)',
    ]))
    DUMP_CHUNK_RE = re.compile(' +'.join([
        r'(?P<filename>\S+):(?P<lineno>[0-9]+):',
        r'\|(?P<level>[0-9]+)\|(?: (?P<address>\w+):)?',
        r'[0-9a-f]+:',
        r'(?P<data>(?:[0-9a-f]{2} *){1,16})',
    ]))

    def __init__(self) -> None:
        """Create an empty log info object."""
        self.dumps = {} #type: Dict[str, List[str]]

    def add_dump(self, name: str, hex_data: str) -> None:
        """Add a hex dump."""
        self.dumps.setdefault(name, []).append(hex_data)

    def read_dump(self,
                  filename: str,
                  lines: Iterator[Tuple[int, str]],
                  length: int) -> str:
        """Read a hex dump. Return the hex data.

        This method consumes the data dump lines from lines.
        """
        acc = ''
        remaining = length
        while remaining > 0:
            lineno, line = next(lines)
            m = self.DUMP_CHUNK_RE.match(line)
            if not m:
                raise Exception(f'{filename}:{lineno}: not a dump chunk as expected')
            acc += m.group('data')
            remaining -= 16
        plain = acc.replace(' ', '')
        assert len(plain) == length * 2
        return plain

    def read_file_contents(self,
                           filename: str,
                           lines: Iterator[Tuple[int, str]]) -> None:
        """Read lines from a log file and store the information we find.

        The iterator lines delivers a stream of lines with their line numbers.
        """
        for _lineno, line in lines:
            m = self.DUMPING_RE.match(line)
            if m:
                what = m.group('what')
                hex_data = self.read_dump(filename, lines,
                                          int(m.group('length')))
                self.add_dump(what, hex_data)

    def read_file(self, filename: str) -> None:
        """Read a log file and store the information we find."""
        with open(filename) as input_:
            self.read_file_contents(filename, enumerate(input_, 1))


def parse_log_file(filename: str) -> Info:
    """Parse a log of ssl_client2 or ssl_server2."""
    info = Info()
    info.read_file(filename)
    return info
