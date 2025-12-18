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

def build_library(build_dir, toolchain_file, named_config):
    config_file_path = build_dir + '/code_size_crypto_config.h'

    subprocess.check_call(['cp', 'include/psa/crypto_config.h', config_file_path])
    subprocess.check_call(['scripts/config.py', '-f', config_file_path, named_config])
    subprocess.check_call(['cmake', '.', '-B' + build_dir,
                           '-DCMAKE_TOOLCHAIN_FILE=' + toolchain_file,
                           '-DENABLE_PROGRAMS=NO',
                           '-DTF_PSA_CRYPTO_CONFIG_FILE=' + config_file_path])
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
    BUILD_DIR = 'build-code-size'

    parser = argparse.ArgumentParser(
        description='Generate a code size report in JSON format')

    parser.add_argument('-s', '--size-cmd',
                        help='Size command to use (default arm-none-eabi-size)',
                        default='arm-none-eabi-size')
    parser.add_argument('-t', '--toolchain-file',
                        help='CMake toolchain file to use for building',
                        default='framework/platform/arm-gcc-m55.cmake')
    parser.add_argument('-c', '--config-name',
                        help='Named config to use for size measurement.',
                        default='baremetal_size')

    args = parser.parse_args()

    build_library(BUILD_DIR, args.toolchain_file, args.config_name)
    generate_sizes(BUILD_DIR, args.size_cmd)
    display_sizes(BUILD_DIR)
