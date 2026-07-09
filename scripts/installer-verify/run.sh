#!/bin/bash
# Container entrypoint: dispatches to the corpus or adversarial runner.
# See scripts/verify-installers.sh (the host-side orchestrator) for the
# full contract each subcommand expects.
set -u

mode="${1:-}"
shift || true

case "$mode" in
    corpus) exec /usr/local/bin/run-corpus.sh "$@" ;;
    adversarial) exec /usr/local/bin/run-adversarial.sh "$@" ;;
    *)
        echo "run.sh: unknown mode '$mode' (expected corpus|adversarial)" >&2
        exit 64
        ;;
esac
