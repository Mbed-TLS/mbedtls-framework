#!/usr/bin/env python3
"""Generate a code size report for the supplied library file, using the given
size tool, and write it in JSON format to the given output file.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import json
import subprocess
import sys

def get_size_output(size_cmd: str, library_file: str):
    """Run the size command on the library and get its output"""
    output = subprocess.check_output([size_cmd, library_file])
    return str(output, 'UTF-8')

def size_breakdown(size_output: str):
    """Convert the output of the size command to a dictionary like the following:
    {'filename.c.obj' : {'text': 123, 'data': 456, 'bss': 789}}"""

    sizes = {}

    for line in size_output.splitlines()[1:]:
        row = line.split()
        obj_file_name = row[5]
        text_size = int(row[0])
        data_size = int(row[1])
        bss_size = int(row[2])

        sizes[obj_file_name] = {'text': text_size, 'data': data_size, 'bss': bss_size}

    return sizes

def write_out_results(sizes: dict, output_file: str):
    """Write out the sizes in JSON to the output file"""
    sizes_json = json.dumps(sizes, indent=4)

    with open(output_file, "w") as out:
        out.write(sizes_json)

def main():
    parser = argparse.ArgumentParser(
        description='Generate a code size report in JSON format')

    parser.add_argument("-o", "--output-file",
                        help="Filename of the report to generate",
                        default='code_size.json')

    parser.add_argument("-s", "--size-cmd",
                        help="Size command to use (e.g. arm-none-eabi-size)",
                        required=True)

    parser.add_argument("-l", "--library-file",
                        help="Library file to generate report from",
                        required=True)

    args = parser.parse_args()

    sizes = size_breakdown(get_size_output(args.size_cmd, args.library_file))

    write_out_results(sizes, args.output_file)

if __name__ == "__main__":
    main()

