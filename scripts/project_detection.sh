# project-detection.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Purpose
#
# This script contains functions for shell scripts to
# help detect which project (Mbed TLS, TF-PSA-Crypto)
# or which Mbed TLS branch they are in.

# Project detection
read_project_name_file () {
    PROJECT_NAME_FILE='../../scripts/project_name.txt'
    if read -r PROJECT_NAME < "$PROJECT_NAME_FILE"; then :; else
        echo "$PROJECT_NAME_FILE does not exist... Exiting..." >&2
        exit 1
    fi
}

in_mbedtls_repo () {
    read_project_name_file
    test "$PROJECT_NAME" = "Mbed TLS"
}

in_tf_psa_crypto_repo () {
    read_project_name_file
    test "$PROJECT_NAME" = "TF-PSA-Crypto"
}
