## Common shell functions used by demo scripts programs/*/*.sh.

## How to write a demo script
## ==========================
##
## Include this file near the top of each demo script:
##   . "${0%/*}/demo_common.sh"
##
## Start with a "msg" call that explains the purpose of the script.
## Then call the "depends_on" function to ensure that all config
## dependencies are met.
##
## As the last thing in the script, call the cleanup function.
##
## You can use the functions and variables described below.

set -e -u

PROJECT_NAME_FILE="scripts/project_name.txt"

# Check is $1 is either an Mbed TLS or TF-PSA-Crypto root folder.
is_valid_root () {
  if [ -f "$1/$PROJECT_NAME_FILE" ]; then
    return 0;
  else
    return 1;
  fi
}

# Check if $1 is the root of the project specified by $2.
check_root_type () {
  read -r PROJECT_NAME < "$1/$PROJECT_NAME_FILE"
  if [ "$PROJECT_NAME" = "$2" ]; then
    return 0;
  else
    return 1;
  fi
}

need_query_compile_time_config () {
  if [ $NEED_QUERY_COMPILE_TIME_CONFIG -eq 1 ]; then
    return 0;
  else
    return 1;
  fi
}

## At the end of the while loop below $root_dir will point to the root directory
## of either the Mbed TLS/TF-PSA-Crypto source tree.
root_dir="${0%/*}"
## Find a nice path to the root directory, avoiding unnecessary "../".
##
## The code supports demo scripts nested up to 4 levels deep.
##
## The code works no matter where the demo script is relative to the current
## directory, even if it is called with a relative path.
##
## This search is based on the fact that both Mbed TLS and TF-PSA-Crypto has
## a file in "<root>/scripts/project_name.txt" which contains the name of the
## project. We take advantage of this file to check if we reached the right path.
n=5
while true; do
  if [ $n -eq 0 ]; then
    echo >&2 "This doesn't seem to be an Mbed TLS source tree."
    exit 125
  fi
  if is_valid_root "$root_dir"; then
    # If we're a valid root_dir and it's the Mbed TLS one, then we're done
    if check_root_type "$root_dir" "Mbed TLS"; then
      break;
    else
      # If we reached the TF-PSA-Crypto root folder and the script that sourced
      # this file does not need query_compile_time_config (which is only available
      # in Mbed TLS repo) then we're done.
      if ! need_query_compile_time_config; then
        break;
      fi
    fi
  fi
  n=$((n - 1))
  case $root_dir in
    .) root_dir="..";;
    ..|?*/..) root_dir="$root_dir/..";;
    ?*/*) root_dir="${root_dir%/*}";;
    /*) root_dir="/";;
    *) root_dir=".";;
  esac
done

## Keep track of the root directory type in a variable.
if check_root_type $root_dir "Mbed TLS"; then
  IS_MBEDTLS_ROOT=1
else
  IS_MBEDTLS_ROOT=0
fi

## msg LINE...
## msg <TEXT_ORIGIN
## Display an informational message.
msg () {
  if [ $# -eq 0 ]; then
    sed 's/^/# /'
  else
    for x in "$@"; do
      echo "# $x"
    done
  fi
}

## run "Message" COMMAND ARGUMENT...
## Display the message, then run COMMAND with the specified arguments.
run () {
    echo
    echo "# $1"
    shift
    echo "+ $*"
    "$@"
}

## Like '!', but stop on failure with 'set -e'
not () {
  if "$@"; then false; fi
}

## run_bad "Message" COMMAND ARGUMENT...
## Like run, but the command is expected to fail.
run_bad () {
  echo
  echo "$1 This must fail."
  shift
  echo "+ ! $*"
  not "$@"
}

## $programs_dir is the directory containing the sample programs.
## Assume an in-tree build.
programs_dir="$root_dir/programs"

## config_has SYMBOL...
## Succeeds if the library configuration has all SYMBOLs set.
##
## Note: "query_compile_time_config" is only available when in Mbed TLS project,
## so "config_has" is not available in TF-PSA-Crypto one.
config_has () {
  for x in "$@"; do
    "$programs_dir/test/query_compile_time_config" "$x"
  done
}

## depends_on SYMBOL...
## Exit if the library configuration does not have all SYMBOLs set.
depends_on () {
  m=
  for x in "$@"; do
    if ! config_has "$x"; then
      m="$m $x"
    fi
  done
  if [ -n "$m" ]; then
    cat >&2 <<EOF
$0: this demo requires the following
configuration options to be enabled at compile time:
 $m
EOF
    # Exit with a success status so that this counts as a pass for run_demos.py.
    exit
  fi
}

## Add the names of files to clean up to this whitespace-separated variable.
## The file names must not contain whitespace characters.
files_to_clean=

## Call this function at the end of each script.
## It is called automatically if the script is killed by a signal.
cleanup () {
  rm -f -- $files_to_clean
}



################################################################
## End of the public interfaces. Code beyond this point is not
## meant to be called directly from a demo script.

trap 'cleanup; trap - HUP; kill -HUP $$' HUP
trap 'cleanup; trap - INT; kill -INT $$' INT
trap 'cleanup; trap - TERM; kill -TERM $$' TERM

if [ $IS_MBEDTLS_ROOT -eq 1 ] && config_has MBEDTLS_ENTROPY_NV_SEED; then
  # Create a seedfile that's sufficiently long in all library configurations.
  # This is necessary for programs that use randomness.
  # Assume that the name of the seedfile is the default name.
  files_to_clean="$files_to_clean seedfile"
  dd if=/dev/urandom of=seedfile ibs=64 obs=64 count=1
fi
