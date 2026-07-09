#!/bin/bash

root_dir=$(dirname "$0")/..
cd $root_dir

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

git add docs/requirements.txt

git commit -s -m "Update Python packages for docs"
