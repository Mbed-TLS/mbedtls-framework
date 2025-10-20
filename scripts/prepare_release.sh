#!/bin/bash

print_usage()
{
    cat <<EOF
Usage: $0 [OPTION]...
Prepare the source tree for a release.

Options:
  -r    Prepare for release
  -u    Prepare for development (undo the release preparation)
EOF
}

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -eu

# Portable inline sed. Helper function that will automatically pre-pend
# an empty string as the backup suffix (required by macOS sed).
psed() {
    # macOS sed does not offer a version
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    # macOS/BSD sed
    else
        local file="${@: -1}"
        local args=("${@:1:$#-1}")
        sed -i '' "${args[@]}" "$file"
    fi
}

if [ $# -eq 0 ] || [ "$1" = "--help" ]; then
    print_usage
    exit
fi

unrelease=0 # if 1 then we are in development mode,
           # if 0 then we are in release mode
while getopts ru OPTLET; do
    case $OPTLET in
        u) unrelease=1;;
        r) unrelease=0;;
        \?)
            echo 1>&2 "$0: unknown option: -$OPTLET"
            echo 1>&2 "Try '$0 --help' for more information."
            exit 3;;
    esac
done

#### .gitignore processing ####
for GITIGNORE in $(git ls-files -- '*.gitignore'); do
    if [ "$unrelease" -eq 1 ]; then
        psed '/###START_COMMENTED_GENERATED_FILES###/,/###END_COMMENTED_GENERATED_FILES###/s/^#//' "$GITIGNORE"
        psed 's/###START_COMMENTED_GENERATED_FILES###/###START_GENERATED_FILES###/' "$GITIGNORE"
        psed 's/###END_COMMENTED_GENERATED_FILES###/###END_GENERATED_FILES###/' "$GITIGNORE"
    else
        psed '/###START_GENERATED_FILES###/,/###END_GENERATED_FILES###/s/^/#/' "$GITIGNORE"
        psed 's/###START_GENERATED_FILES###/###START_COMMENTED_GENERATED_FILES###/' "$GITIGNORE"
        psed 's/###END_GENERATED_FILES###/###END_COMMENTED_GENERATED_FILES###/' "$GITIGNORE"
    fi
done

#### Build scripts ####

# GEN_FILES defaults on (non-empty) in development, off (empty) in releases
if [ "$unrelease" -eq 1 ]; then
    r=' yes'
else
    r=''
fi
psed "s/^\(GEN_FILES[ ?:]*=\)\([^#]*\)/\1$r/" Makefile */Makefile

# GEN_FILES defaults on in development, off in releases
if [ "$unrelease" -eq 1 ]; then
    r='ON'
else
    r='OFF'
fi
psed "/[Oo][Ff][Ff] in development/! s/^\( *option *( *GEN_FILES  *\"[^\"]*\"  *\)\([A-Za-z0-9][A-Za-z0-9]*\)/\1$r/" CMakeLists.txt
