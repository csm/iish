#!/usr/bin/env bash
# Milestone 7 (PLAN.md "Corpus as test suite"): run real, high-profile
# installer scripts from the cached corpus (corpus/cache/, no network
# needed to obtain them) through the real iish binary, and confirm each
# ends up in a state that matches what we've pinned as its current,
# expected outcome. Also runs a handful of synthetic "sneaky installer"
# scripts that try to abuse iish's policy, and confirms none of them
# work.
#
# Every run happens inside a fresh, network-disabled Docker container
# (see scripts/installer-verify/), so a policy bug can do no lasting
# damage to the machine running this script and the whole thing is
# reproducible without a network connection once the image is built.
#
# This is the same script CI runs (.github/workflows/installer-verify.yml)
# and is meant to be run by hand too -- on Linux or on macOS with Docker
# Desktop -- so it only assumes bash + docker, nothing GNU-specific and
# nothing newer than the bash 3.2 macOS still ships as /bin/bash.
#
# Usage:
#   scripts/verify-installers.sh                 # everything
#   scripts/verify-installers.sh --only rustup    # one corpus installer
#   scripts/verify-installers.sh --only adversarial:root-wipe
#   scripts/verify-installers.sh --verbose        # always show container output
#   scripts/verify-installers.sh --keep-image     # skip the final `docker rmi`
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_tag="iish-verify:local"
verbose=0
keep_image=0
only=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --verbose | -v) verbose=1 ;;
        --keep-image) keep_image=1 ;;
        --only)
            shift
            only="${1:-}"
            ;;
        -h | --help)
            sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "verify-installers: unknown argument '$1'" >&2
            exit 64
            ;;
    esac
    shift
done

if ! command -v docker >/dev/null 2>&1; then
    echo "verify-installers: docker is required (Docker Desktop on macOS, docker-ce on Linux)" >&2
    exit 1
fi

pass_count=0
fail_count=0

pass() {
    pass_count=$((pass_count + 1))
    printf '  \033[32mPASS\033[0m  %s\n' "$1"
}

fail() {
    fail_count=$((fail_count + 1))
    printf '  \033[31mFAIL\033[0m  %s\n' "$1"
}

show_log() {
    # Full container transcript, indented; always shown on failure, only
    # on success when --verbose was given.
    sed 's/^/        /' "$1"
}

want() {
    # $1 = category (self-check|corpus|adversarial), $2 = item name.
    # --only accepts a bare item name, a bare category (every item in
    # it), or "category:name" for one adversarial scenario. Written with
    # plain `if`s (not a `&&`/`||` chain) so it behaves the same under
    # `set -e` on every bash, including macOS's bash 3.2.
    if [ -z "$only" ]; then
        return 0
    fi
    if [ "$only" = "$1" ]; then
        return 0
    fi
    if [ "$only" = "$2" ]; then
        return 0
    fi
    if [ "$only" = "$1:$2" ]; then
        return 0
    fi
    return 1
}

echo "==> Building the installer-verify image ($image_tag)"
docker build -q -f "$repo_root/scripts/installer-verify/Dockerfile" -t "$image_tag" "$repo_root" >/dev/null

cleanup() {
    if [ "$keep_image" -eq 0 ]; then
        docker rmi "$image_tag" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------
# Harness self-check: a synthetic, offline "installer" built entirely
# from iish's currently-supported grammar, which really does run to
# completion today. Its only job is to prove the "iish finished; now
# check the program it installed" path in this script actually works --
# otherwise that path stays completely unexercised until a real corpus
# script gets far enough to reach it (see the corpus section below).
# ---------------------------------------------------------------------
if want self-check self-check; then
    echo "==> Harness self-check"
    log="$(mktemp)"
    if docker run --rm --network none "$image_tag" \
        corpus yes /opt/fixtures/toy-installer.sh toytool >"$log" 2>&1; then
        pass "self-check: iish ran the toy installer and the resulting program is usable"
        [ "$verbose" -eq 1 ] && show_log "$log"
    else
        fail "self-check: the harness itself is broken (this should always succeed) -- see log"
        show_log "$log"
    fi
    rm -f "$log"
fi

# ---------------------------------------------------------------------
# Corpus: real installer scripts, run for real (not --dry-run) through
# iish, non-interactively (--yes: approve every ask, the posture a CI
# gate or unattended provisioning run would take). None of the 17
# scripts in corpus/cache/ run to completion through iish today --
# iish's evaluator still denies control flow and several expansions
# outright (PLAN.md milestone 7 is "should run the majority of the
# corpus to completion"; today is 0/17). So for each of these we pin
# *why* it currently stops, as a regression guard: if the reason changes
# without this file being updated, either iish's behavior regressed, or
# it progressed -- both are worth a human looking at. If a script ever
# runs to completion, the paired verify command decides pass/fail for
# real, exactly as it eventually should for the whole corpus.
# ---------------------------------------------------------------------
corpus_names="rustup starship zoxide atuin deno pnpm nvm"

set_corpus_expectation() {
    verify_cmd=()
    case "$1" in
        rustup)
            # `2> /dev/null` stderr redirects are implemented now (so
            # the redirect that used to stop this one no longer does):
            # `has_local 2>/dev/null` actually calls into has_local's
            # body, which trips on `local`, a shell builtin iish has no
            # binary to exec and doesn't implement.
            expected_reason="\`local\` is a shell builtin; iish does not implement it"
            verify_cmd=(rustc --version)
            ;;
        zoxide)
            # Reached from inside a call to zoxide's own \`main\`
            # function (a real function call, not just its definition)
            # -- see the indented DENY in \`iish --dry-run\`'s output.
            # `&&`/`||` are implemented now; this trips on `main`'s own
            # `"$@"`, a special parameter (only plain `$VAR`/`${VAR}` is
            # implemented).
            expected_reason="special parameters (\`\$?\`, \`\$#\`, \`\$@\`, \`\$*\`, ...) are not supported yet"
            verify_cmd=(zoxide --version)
            ;;
        pnpm)
            # `if`/`test`/`[` (including `-t`) and bare `VAR=value`
            # assignment are all implemented now; this trips on the next
            # unimplemented construct, a command substitution
            # (`$(tty_mkbold 34)`) as the assigned value.
            expected_reason="command substitution is not supported yet"
            verify_cmd=(pnpm --version)
            ;;
        nvm)
            # Reached from inside a brace group actually running now,
            # into the very first `if` -- `if`/`[`/`||` are implemented;
            # this trips on `$BASH_VERSION`, a real environment variable
            # that's genuinely unset in iish's own process (iish isn't
            # bash), matching what a real, non-bash `sh` would see too.
            expected_reason="\`\$BASH_VERSION\` is unset"
            verify_cmd=(bash -lc 'source "$HOME/.nvm/nvm.sh" 2>/dev/null; command -v nvm')
            ;;
        starship)
            # `set -eu` and bare `VAR=value` assignment are implemented
            # now; this trips on the next unimplemented construct, a
            # command substitution (`$(tput bold ...)`) as the assigned
            # value.
            expected_reason="command substitution is not supported yet"
            verify_cmd=(starship --version)
            ;;
        atuin)
            # Bare `VAR=value` assignment is implemented now; this trips
            # on the next unimplemented construct, a `for` loop.
            expected_reason="for-loops are not implemented yet"
            verify_cmd=(atuin --version)
            ;;
        deno)
            # `if`/`test`/`[` and `&&`/`||` are implemented now; this
            # trips on the condition's `!` pipeline negation, the next
            # unimplemented construct.
            expected_reason="\`!\` pipeline negation is not implemented yet"
            verify_cmd=(deno --version)
            ;;
        *)
            echo "verify-installers: no pinned expectation for corpus installer '$1'" >&2
            exit 1
            ;;
    esac
}

echo "==> Corpus (real installers, real iish, --yes)"
for name in $corpus_names; do
    if want corpus "$name"; then
        set_corpus_expectation "$name"
        log="$(mktemp)"
        status=0
        docker run --rm --network none \
            -v "$repo_root/corpus/cache:/corpus:ro" \
            "$image_tag" corpus yes "/corpus/$name.sh" "${verify_cmd[@]}" >"$log" 2>&1 || status=$?

        case "$status" in
            0)
                pass "$name: iish ran it to completion AND \`${verify_cmd[*]}\` succeeded -- milestone 7 progress, update the pin"
                [ "$verbose" -eq 1 ] && show_log "$log"
                ;;
            2)
                fail "$name: iish ran it to completion but \`${verify_cmd[*]}\` FAILED -- policy let something through that isn't actually usable"
                show_log "$log"
                ;;
            1)
                if grep -qF "$expected_reason" "$log"; then
                    pass "$name: stopped as pinned (\"$expected_reason\")"
                    [ "$verbose" -eq 1 ] && show_log "$log"
                else
                    fail "$name: stopped for an UNEXPECTED reason (expected \"$expected_reason\") -- update or investigate the pin"
                    show_log "$log"
                fi
                ;;
            *)
                fail "$name: container exited $status unexpectedly"
                show_log "$log"
                ;;
        esac
        rm -f "$log"
    fi
done

# ---------------------------------------------------------------------
# Adversarial: synthetic installer scripts that attempt real attacks
# using only iish's currently-supported grammar (no if/for/functions --
# those would just get denied for being unsupported syntax before ever
# reaching the attack, which would prove nothing). Each runs twice: once
# with --yes (does a hard Deny survive an operator who trusts the
# installer completely?) and once with --no (does an ask-gated
# protection fail safe when nobody is watching?). See
# corpus/adversarial/*.sh for what each one tries.
# ---------------------------------------------------------------------
adversarial_names="root-wipe env-file-inject-persistence overwrite-ssh-key-outside-grammar symlink-escape-rm symlink-escape-chmod"

set_adversarial_setup_and_check() {
    setup=""
    check="true"
    case "$1" in
        overwrite-ssh-key-outside-grammar)
            setup='mkdir -p "$HOME/.ssh"; printf "legit-authorized-key\n" > "$HOME/.ssh/authorized_keys"'
            check='[ "$(cat "$HOME/.ssh/authorized_keys" 2>/dev/null)" = "legit-authorized-key" ]'
            ;;
        symlink-escape-rm)
            setup='mkdir -p "$HOME/victim"; printf "canary-marker\n" > "$HOME/victim/marker.txt"'
            check='[ "$(cat "$HOME/victim/marker.txt" 2>/dev/null)" = "canary-marker" ]'
            ;;
        symlink-escape-chmod)
            setup='mkdir -p "$HOME/victim2"; printf "canary-marker2\n" > "$HOME/victim2/marker2.txt"; chmod 600 "$HOME/victim2/marker2.txt"'
            check='[ "$(cat "$HOME/victim2/marker2.txt" 2>/dev/null)" = "canary-marker2" ] && [ "$(stat -c %a "$HOME/victim2/marker2.txt" 2>/dev/null)" = "600" ]'
            ;;
        *) ;; # root-wipe, env-file-inject-persistence: nothing to pre-place
    esac
}

echo "==> Adversarial (synthetic sneaky installers)"
for name in $adversarial_names; do
    if want adversarial "$name"; then
        set_adversarial_setup_and_check "$name"
        for mode in yes no; do
            home_dir="$(mktemp -d)"
            chmod 777 "$home_dir"
            log="$(mktemp)"
            status=0
            docker run --rm --network none \
                -v "$repo_root/corpus/adversarial:/adversarial:ro" \
                -v "$home_dir:/home/tester" \
                "$image_tag" adversarial "$mode" "/adversarial/$name.sh" "$setup" "$check" >"$log" 2>&1 || status=$?

            # setup/check snippets and iish itself all ran as the
            # container's unprivileged "tester" user, which can leave
            # files under $home_dir owned by a uid the host user isn't
            # (a directory like .ssh made with the default 755 blocks
            # a different-uid host process from unlinking anything
            # inside it, even though $home_dir itself is world-writable).
            # Recursively opening permissions from *inside* the image,
            # as the same "tester" user that owns everything, sidesteps
            # any host/container uid mismatch without needing sudo.
            docker run --rm --network none --entrypoint chmod \
                -v "$home_dir:/home/tester" \
                "$image_tag" -R u+rwX,go+rwX /home/tester >/dev/null 2>&1 || true
            rm -rf "$home_dir" || true

            if [ "$status" -eq 0 ]; then
                pass "$name (--$mode): attack refused, nothing iish didn't own was touched"
                [ "$verbose" -eq 1 ] && show_log "$log"
            else
                fail "$name (--$mode): attack was NOT fully blocked -- see log"
                show_log "$log"
            fi
            rm -f "$log"
        done
    fi
done

echo
echo "==> $pass_count passed, $fail_count failed"
[ "$fail_count" -eq 0 ]
