#!/usr/bin/env python3
"""Build the library for Cortex-M55 using the toolchain file in
framework/platform and measure and print the code size using the
existing scripts.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import json
import os
import subprocess

def build_library(build_dir, toolchain_file):
    subprocess.check_call(['cmake', '.', '-B' + build_dir,
                           '-DCMAKE_TOOLCHAIN_FILE=framework/platform/' + toolchain_file,
                           '-DENABLE_PROGRAMS=NO'])
    subprocess.check_call(['cmake', '--build', build_dir, '-j' + str(os.cpu_count())])

def generate_sizes(build_dir, size_cmd):
    subprocess.check_call(['framework/scripts/generate_code_size_report.py',
                           '--output-file', build_dir + '/code_size.json',
                           '--library-file', build_dir + '/core/libtfpsacrypto.a',
                           '--size-cmd', size_cmd])

def display_sizes(build_dir):
    subprocess.check_call(['framework/scripts/show_code_size.py',
                           build_dir + '/code_size.json'])

if __name__ == '__main__':
    BUILD_DIR = 'build-code-size-m55'

    parser = argparse.ArgumentParser(
        description='Generate a code size report in JSON format')

    parser.add_argument('-s', '--size-cmd',
                        help='Size command to use (default arm-none-eabi-size)',
                        default='arm-none-eabi-size')

    args = parser.parse_args()

    build_library(BUILD_DIR, 'arm-gcc-m55.cmake')
    generate_sizes(BUILD_DIR, args.size_cmd)
    display_sizes(BUILD_DIR)
