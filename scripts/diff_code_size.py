#!/usr/bin/env python3
"""Examine 2 code size reports and print the difference between them.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import json
import sys

def load_sizes(json_file):
    with open(json_file) as f:
        json_sizes = f.read()

    sizes = json.loads(json_sizes)
    return sizes

def generate_diff_table(sizes_a, sizes_b):
    table = []
    total_size_a = 0
    total_size_b = 0

    for file in sizes_a:
        size_a = (sizes_a[file]['text']
                  + sizes_a[file]['data']
                  + sizes_a[file]['bss'])
        total_size_a += size_a

        if file in sizes_b:
            size_b = (sizes_b[file]['text']
                      + sizes_b[file]['data']
                      + sizes_b[file]['bss'])
            size_diff = size_b - size_a

            if size_diff != 0:
                table.append((file.split('.')[0], size_a, size_b, size_diff,
                              (size_diff * 100.0 / size_a)))
        else:
            # This file is only in A, so there's a code size decrease
            table.append((file.split('.')[0], size_a, 0, -size_a, -100.0))

    for file in sizes_b:
        size_b = (sizes_b[file]['text']
                  + sizes_b[file]['data']
                  + sizes_b[file]['bss'])
        total_size_b += size_b

        if file not in sizes_a:
            # This file is only in B, so there's a code size increase
            table.append((file.split('.')[0], 0, size_b, size_b, 100.0))

    total_size_diff = total_size_b - total_size_a
    table.append(('TOTAL', total_size_a, total_size_b, total_size_diff,
                  (total_size_diff * 100.0 / total_size_a)))

    return table

def display_diff_table(table):
    table_line_format = '{:<40} {:>8} {:>8} {:>+8} {:>+8.2f}%'

    print('{:<40} {:>8} {:>8} {:>8} {:>9}'.format(
        'Module', 'Old', 'New', 'Delta', '% Delta'))

    for line in table:
        print(table_line_format.format(*line))

def main():
    if len(sys.argv) < 3:
        print('Error: Less than 2 JSON files supplied.', file=sys.stderr)
        sys.exit(1)

    sizes_a = load_sizes(sys.argv[1])
    sizes_b = load_sizes(sys.argv[2])

    display_diff_table(generate_diff_table(sizes_a, sizes_b))

if __name__ == '__main__':
    main()
