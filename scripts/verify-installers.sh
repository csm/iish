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
#   scripts/verify-installers.sh                 # the hermetic, offline suite
#   scripts/verify-installers.sh --only rustup    # one corpus installer
#   scripts/verify-installers.sh --only adversarial:root-wipe
#   scripts/verify-installers.sh --verbose        # always show container output
#   scripts/verify-installers.sh --keep-image     # skip the final `docker rmi`
#   scripts/verify-installers.sh --live           # ONLY the live-install job
#
# By default this runs entirely offline (`docker run --network none`): a
# self-check, the corpus regression pins, and the adversarial corpus,
# none of which touch the network. `--live` instead runs the separate
# live-install job, which DOES reach the real internet to install a
# curated, trustworthy, user-space installer end to end and verify the
# program it produces actually runs -- see the "Live installs" section.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_tag="iish-verify:local"
verbose=0
keep_image=0
only=""
live=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --verbose | -v) verbose=1 ;;
        --keep-image) keep_image=1 ;;
        --live) live=1 ;;
        --only)
            shift
            only="${1:-}"
            ;;
        -h | --help)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
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
xfail_count=0
results=()

pass() {
    pass_count=$((pass_count + 1))
    results+=("PASS|$1")
    printf '  \033[32mPASS\033[0m  %s\n' "$1"
}

fail() {
    fail_count=$((fail_count + 1))
    results+=("FAIL|$1")
    printf '  \033[31mFAIL\033[0m  %s\n' "$1"
}

xfail() {
    # Expected failure: the run stopped exactly where we've pinned it.
    # Reported honestly as a failure to install (never as a PASS), but
    # it doesn't fail the suite -- only a pin *breaking* does. This is
    # what keeps the suite green-by-default while the corpus can't yet
    # run to completion (milestone 7), without hiding that fact.
    xfail_count=$((xfail_count + 1))
    results+=("XFAIL|$1")
    printf '  \033[33mXFAIL\033[0m %s\n' "$1"
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
# Live installs (opt-in, --live): the one place this harness reaches the
# real internet. Each installer here is a curated, trustworthy, entirely
# user-space one that iish can drive to *completion* -- it downloads a
# real release, installs it under $HOME, and then we run the installed
# program to prove it actually works. This is the genuine "green" the
# offline corpus can only gesture at: a real installer, installed for
# real, verified by running it.
#
# It is deliberately a SEPARATE job (its own workflow, not a PR gate):
# it depends on live upstreams (GitHub releases, their API rate limits),
# so an upstream hiccup must never red the hermetic suite that guards
# iish's own behavior. iish runs with --subprocess=allow here (the
# unattended-provisioning posture: approve the tar/grep/... an installer
# shells out to), still never handing anything to a shell.
# ---------------------------------------------------------------------
live_names="zoxide starship"

set_live_expectation() {
    # Per-installer: the docker env that makes it non-interactive and
    # user-space, and the command that proves the install worked.
    verify_cmd=()
    live_env=(-e "HOME=/home/tester"
        -e "PATH=/home/tester/.local/bin:/usr/local/bin:/usr/bin:/bin"
        -e "IISH_EXTRA_FLAGS=--subprocess=allow")
    case "$1" in
        zoxide)
            # Installs to ~/.local/bin by default, no prompt.
            verify_cmd=(zoxide --version)
            ;;
        starship)
            # FORCE skips its y/n prompt; BIN_DIR makes it user-space.
            live_env+=(-e "FORCE=1" -e "BIN_DIR=/home/tester/.local/bin")
            verify_cmd=(starship --version)
            ;;
        *)
            echo "verify-installers: no live expectation for '$1'" >&2
            exit 1
            ;;
    esac
}

if [ "$live" -eq 1 ]; then
    echo "==> Live installs (real network, real upstreams)"
    for name in $live_names; do
        if want live "$name"; then
            set_live_expectation "$name"
            log="$(mktemp)"
            status=0
            # NOTE: no `--network none` here -- this job needs the internet.
            docker run --rm \
                "${live_env[@]}" \
                -v "$repo_root/corpus/cache:/corpus:ro" \
                "$image_tag" corpus yes "/corpus/$name.sh" "${verify_cmd[@]}" >"$log" 2>&1 || status=$?
            case "$status" in
                0)
                    pass "$name: real end-to-end install completed AND \`${verify_cmd[*]}\` works"
                    [ "$verbose" -eq 1 ] && show_log "$log"
                    ;;
                2)
                    fail "$name: iish ran it to completion but \`${verify_cmd[*]}\` FAILED -- the installed program isn't usable"
                    show_log "$log"
                    ;;
                *)
                    fail "$name: did not complete a live install (container exit $status) -- an upstream/network issue, or a real iish gap"
                    show_log "$log"
                    ;;
            esac
            rm -f "$log"
        fi
    done

    echo
    echo "==> Summary"
    for r in ${results[@]+"${results[@]}"}; do
        status="${r%%|*}"
        name="${r#*|}"
        case "$status" in
            PASS) printf '  \033[32mPASS\033[0m  %s\n' "$name" ;;
            *) printf '  \033[31mFAIL\033[0m  %s\n' "$name" ;;
        esac
    done
    echo
    echo "==> $pass_count passed, $fail_count failed"
    [ "$fail_count" -eq 0 ]
    exit
fi

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
# scripts in corpus/cache/ run to *completion* through iish today, but
# not because iish can't follow their logic anymore -- with functions,
# loops, command substitution, pipelines, parameter expansion, `local`,
# `read`, `cd`, and the rest of milestone 7 landed, every one of these
# now runs its full platform-detection and setup logic and stops only
# at a genuine *external* boundary:
#
#   * the network -- these containers run with --network none, so the
#     moment an installer reaches its actual download it fails to
#     connect (rustup, zoxide, pnpm). With a network they would proceed
#     past this point;
#   * an interactive prompt -- starship reads a y/n confirmation from
#     /dev/tty, which an unattended container does not have;
#   * `curl ... | sh` -- atuin's real installer is a tiny bootstrap that
#     pipes a second stage straight into a shell, the exact anti-pattern
#     iish exists to refuse; it can never proceed under iish, by design;
#   * a still-unimplemented shell construct -- nvm parallelizes its
#     downloads with background jobs (`&`), which iish doesn't implement
#     yet, and deno bails out itself when neither `unzip` nor `7z` is on
#     the slim image.
#
# So for each we pin *where* it stops as a regression guard: if the
# reason changes without this file being updated, either iish regressed
# or it progressed further -- both worth a human looking at, and both
# FAIL the suite. Stopping at the pinned boundary is reported as XFAIL
# (an expected, known-tracked non-completion -- the installer did not
# actually install anything, so calling it a PASS would be a lie), which
# does not fail the suite. If a script ever runs to completion (e.g. the
# offline-completable ones, once the harness grows a local payload
# mirror), the paired verify command decides pass/fail for real -- and
# the self-check above already exercises that completed-install path
# end to end today.
# ---------------------------------------------------------------------
corpus_names="rustup starship zoxide atuin deno pnpm nvm"

set_corpus_expectation() {
    verify_cmd=()
    case "$1" in
        rustup)
            # Runs the whole downloader/arch/bitness probe, then reaches
            # its real download: `_err=$(curl ... --output "$2" 2>&1)`.
            # iish performs the GET with its own client, which can't
            # connect under --network none, so the substitution fails
            # here. With a network, rustup would continue.
            expected_reason='_err=$(curl $_retry'
            verify_cmd=(rustc --version)
            ;;
        zoxide)
            # Full arch detection and release lookup run; stops inside
            # `_package="$(download_zoxide "${_arch}")"`, i.e. its actual
            # binary download -- a network boundary, not a syntax gap.
            expected_reason='$(download_zoxide'
            verify_cmd=(zoxide --version)
            ;;
        pnpm)
            # Runs its platform detection, then stops fetching the
            # version manifest: `version_json="$(download
            # "https://registry.npmjs.org/@pnpm/exe")"` -- network.
            expected_reason='$(download "https://registry.npmjs.org'
            verify_cmd=(pnpm --version)
            ;;
        nvm)
            # Runs profile detection, the install-dir setup, and the
            # git-vs-script method choice, reaching the download step --
            # which nvm backgrounds with `&` to parallelize. Background
            # jobs are the one construct still unimplemented here.
            expected_reason="background jobs (\`&\`) are not implemented yet"
            verify_cmd=(bash -lc 'source "$HOME/.nvm/nvm.sh" 2>/dev/null; command -v nvm')
            ;;
        starship)
            # Runs platform/arch detection and prints its install
            # summary, then asks to confirm: `read -r yn < /dev/tty`.
            # An unattended container has no controlling terminal, so
            # the read fails -- an interactive boundary, not a syntax gap.
            expected_reason="read: could not read a line from"
            verify_cmd=(starship --version)
            ;;
        atuin)
            # atuin's real one-liner installer is `curl ... | sh`: it
            # downloads a second-stage script and pipes it straight into
            # a shell. iish refuses that categorically (its whole reason
            # to exist), so atuin can never proceed under iish by design.
            expected_reason="piping into a shell is exactly what iish exists to replace"
            verify_cmd=(atuin --version)
            ;;
        deno)
            # Runs its full arch/OS detection, then bails out on its own
            # (`exit 1`) because neither `unzip` nor `7z` is present on
            # the slim image -- deno's own precondition check, reached
            # only because iish ran everything up to it.
            expected_reason="either unzip or 7z is required"
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
                    # It stopped for exactly the reason we've pinned.
                    # That still means the installer did NOT actually
                    # install anything, so it's reported as an expected
                    # failure, never a pass -- but only an unexpected
                    # outcome (the pin breaking) fails the suite.
                    xfail "$name: stopped as pinned (\"$expected_reason\") -- installation did not complete (known, tracked failure)"
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
echo "==> Summary"
for r in "${results[@]}"; do
    status="${r%%|*}"
    name="${r#*|}"
    case "$status" in
        PASS) printf '  \033[32mPASS\033[0m  %s\n' "$name" ;;
        XFAIL) printf '  \033[33mXFAIL\033[0m %s\n' "$name" ;;
        *) printf '  \033[31mFAIL\033[0m  %s\n' "$name" ;;
    esac
done

echo
echo "==> $pass_count passed, $xfail_count expected failures (known, tracked), $fail_count failed"
[ "$fail_count" -eq 0 ]
