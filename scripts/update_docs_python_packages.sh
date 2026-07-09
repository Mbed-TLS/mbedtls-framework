#!/bin/bash

FRAMEWORK=$(dirname "$0")/..
source $FRAMEWORK/scripts/project_detection.sh

if is_tf_psa_crypto_root $PWD; then
    echo "Error: This script is only for Mbed TLS"
    exit 1
fi

if is_mbedtls_root $PWD; then :; else
    echo "Error: Must be run from Mbed TLS root"
    exit 1
fi

py_version=$(python --version)

if [[ "$py_version" != *"Python 3.9"* ]]; then
    echo "Error: Python version is not 3.9. Ensure Python version is 3.9 to continue."

    exit 1
fi

# Ensure we have pip-tools
pip install pip-tools

# Get rid of the existing requirements.txt
rm docs/requirements.txt

# Regenerate requirements.txt from requirements.in
pip-compile docs/requirements.in

# If there are any changes, add a commit
if ! git diff --quiet docs/requirements.txt; then
    git add docs/requirements.txt
    git commit -s -m "Update Python packages for docs"
fi
