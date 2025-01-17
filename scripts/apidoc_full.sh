#!/bin/sh

# Generate doxygen documentation with a full mbedtls_config.h (this ensures that every
# available flag is documented, and avoids warnings about documentation
# without a corresponding #define).
#
# /!\ This must not be a Makefile target, as it would create a race condition
# when multiple targets are invoked in the same parallel build.
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -eu

. $(dirname "$0")/project_detection.sh

if in_mbedtls_repo; then
    CONFIG_H='include/mbedtls/mbedtls_config.h'
elif in_tf_psa_crypto_repo; then
    CONFIG_H='include/psa/crypto_config.h'
fi

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

CONFIG_BAK=${CONFIG_H}.bak
cp -p $CONFIG_H $CONFIG_BAK

if in_mbedtls_repo; then
    scripts/config.py realfull
    make apidoc
    mv $CONFIG_BAK $CONFIG_H
elif in_tf_psa_crypto_repo; then
    cd $OUT_OF_SOURCE_DIR
    cmake -DCMAKE_BUILD_TYPE:String=Check -DGEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make tfpsacrypto-apidoc
    mv $TF_PSA_CRYPTO_ROOT_DIR/$CONFIG_BAK $TF_PSA_CRYPTO_ROOT_DIR/$CONFIG_H
fi
