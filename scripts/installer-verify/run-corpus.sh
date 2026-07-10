#!/bin/bash
# Run a real installer script through the real iish binary and, only if
# it runs to completion, check that the program it was supposed to
# install actually works. Exit codes carry the outcome for the host
# script (scripts/verify-installers.sh) to interpret; the full iish
# transcript is always on stdout/stderr for a human (or a `grep` for a
# pinned deny/failure reason) to read.
#
#   0  iish ran the whole script and the verify command succeeded
#      (or no verify command was given)
#   1  iish refused or failed partway through (the expected case for
#      every real corpus script today, since none of them run to
#      completion yet — see PLAN.md milestone 7)
#   2  iish ran the whole script, but the verify command failed: iish's
#      policy let something through that did not actually produce a
#      usable program. Always a bug worth looking at.
set -u

ask_mode="$1"
shift
script="$1"
shift

# Provisioning for the live-install job: some installers require their
# target bin directory to already exist (starship's `check_bin_dir`
# refuses to create it). Creating it up front is exactly the
# unattended-provisioning step a real automated install would do, and
# it's a no-op for the offline corpus (the env var is unset there).
if [ -n "${IISH_PREMAKE_DIR:-}" ]; then
    # shellcheck disable=SC2086  # deliberate word-splitting of the dir list
    mkdir -p ${IISH_PREMAKE_DIR}
fi

# Extra iish flags (e.g. --subprocess=allow for the live-install job) come
# in via the environment so the positional contract stays unchanged.
# shellcheck disable=SC2086  # deliberate word-splitting of the flag list
if ! /usr/local/bin/iish --no-config ${IISH_EXTRA_FLAGS:-} --"$ask_mode" "$script"; then
    echo "run-corpus: iish did not run '$script' to completion"
    exit 1
fi

echo "run-corpus: iish ran '$script' to completion"
if [ "$#" -eq 0 ]; then
    exit 0
fi

# Pick up PATH/env changes the script made via the env-file append
# grammar (milestone 6) before running the verify command.
# shellcheck disable=SC1090
source "$HOME/.bash_profile" 2>/dev/null
# shellcheck disable=SC1090
source "$HOME/.profile" 2>/dev/null
# shellcheck disable=SC1090
source "$HOME/.bashrc" 2>/dev/null

if "$@"; then
    echo "run-corpus: verify command succeeded: $*"
    exit 0
else
    echo "run-corpus: verify command FAILED: $*"
    exit 2
fi
