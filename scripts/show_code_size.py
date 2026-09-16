#!/usr/bin/env python3
"""Parse a JSON code size report and output a pretty-printed table of sizes
for each module along with their totals.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import json
import sys

def display_sizes(json_file):
    with open(json_file) as f:
        json_sizes = f.read()

    sizes = json.loads(json_sizes)

    padded_line = '{:<40} {:>8} {:>8} {:>8} {:>8}'

    print(padded_line.format('file', 'text', 'data', 'bss', 'total'))

    text_total = 0
    data_total = 0
    bss_total = 0
    total_total = 0

    for file in sizes:
        module = file.split('.')[0] # Remove .c.obj extension
        text = sizes[file]['text']
        data = sizes[file]['data']
        bss = sizes[file]['bss']
        print(padded_line.format(module, text, data, bss, text + data + bss))
        text_total += text
        data_total += data
        bss_total += bss
        total_total += text + data + bss

    print(padded_line.format('TOTAL', text_total, data_total, bss_total, total_total))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Error: No JSON file supplied.', file=sys.stderr)
        sys.exit(1)

    display_sizes(sys.argv[1])
