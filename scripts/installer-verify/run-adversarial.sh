#!/bin/bash
# Run a synthetic "sneaky installer" script through the real iish binary
# and confirm the attack it attempts did not work — regardless of
# whether iish refused outright or the script simply ran out of
# statements. `setup_snippet` plants whatever pre-existing state the
# attack targets (e.g. a real ~/.ssh/authorized_keys); `check_snippet`
# is evaluated afterward and must exit 0 if that state is untouched.
# Both run as plain bash -c inside this container, so they can rely on
# real GNU coreutils regardless of what host OS is driving Docker.
#
# Exit 0 only when the attack was refused AND the check snippet
# confirms nothing was touched; exit 1 otherwise (either iish let the
# script run to completion, or — worse — the check snippet found
# damage).
set -u

ask_mode="$1"
shift
script="$1"
shift
setup_snippet="$1"
shift
check_snippet="$1"
shift

if [ -n "$setup_snippet" ]; then
    bash -c "$setup_snippet"
fi

iish_exit=0
/usr/local/bin/iish --no-config --"$ask_mode" "$script" || iish_exit=$?
echo "run-adversarial: iish exit=$iish_exit"

check_exit=0
bash -c "$check_snippet" || check_exit=$?
echo "run-adversarial: victim-check exit=$check_exit (0 means untouched)"

if [ "$iish_exit" -ne 0 ] && [ "$check_exit" -eq 0 ]; then
    echo "run-adversarial: SAFE — attack refused, nothing this run didn't own was touched"
    exit 0
fi
echo "run-adversarial: UNSAFE"
exit 1
