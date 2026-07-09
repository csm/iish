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

`subprocess`, `overwrite`, `network`, `run-created`, `env-file-append`,
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
--network=deny --config path.toml --no-config --dry-run …`, plus
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
               top-level syntax error. Also renders a `Word` to a
               literal string when it needs no unsupported expansion —
               command substitution, most parameter-expansion operators,
               array/positional/special parameters, and unquoted
               globbing are all still rejected, but a plain `$VAR`/
               `${VAR}` reference now resolves against the caller's
               variable map (state.rs's `Session::variables`, this run's
               bare-assignment-tracked values) with a fallback to the
               real process environment — the same fallback `~` already
               gets for `$HOME` — and an outright-unset name is rejected
               rather than silently expanding to empty, matching iish's
               `nounset`-always-on posture.
  policy.rs    The evaluator: walks `parser::ast` node by node and
               produces a Verdict { Allow, Prompt(reason), Deny(reason),
               Group(statements), If(condition, then, elses),
               AndOrList(first, rest) } per top-level statement. `Group`
               is a brace group, a call to a function defined earlier in
               the run (state.rs's `Session` now also carries a function
               table), or a matched `case` arm — not a single compiled
               `Action`, since its nested statements must be evaluated
               one at a time against the live session, exactly like
               top-level statements; the runner (main.rs) recurses for
               it, depth-limited to guard against unbounded
               self-recursion. `If` is `Group`'s counterpart for
               `if`/`elif`/`else`/`fi`: since which branch (if any) runs
               depends on the condition's actual — possibly
               side-effecting — exit status, the runner executes
               `condition` itself (exempted from iish's usual
               abort-on-any-failure posture, matching bash's own
               exemption for a compound command's condition) before
               recursing into whichever branch it selects. `AndOrList` is
               the same deferral for a `first && second || third ...`
               command list: the runner walks it left to right,
               short-circuiting exactly like bash, and only the
               *grammatically last* pipeline's real exit status can trip
               iish's abort-on-failure posture — `false && echo hi`
               survives it (`echo hi` never ran), `true && false` does
               not. `test`/`[ ]` is evaluated natively too, with no side
               effects, and a bare `VAR=value` (or several on one line,
               no command word) assignment is resolved to an `Assign`
               action that just records the value in the session — so a
               `case` value, a condition, or an assigned value made only
               of literal text, `$VAR` reads, and `&&`/`||`/`test` can
               resolve completely. Anything still not implemented
               (pipelines, `for`/`while`/`until`, most redirects, most
               expansions, `VAR=value cmd` prefix assignment, ...) is
               denied here — the Unsupported→deny posture lives in the
               evaluator, not the parser.
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
               DefineFunction, Test, Assign, Noop); exec runs actions in
               Rust — echo/printf rendering, dir creation, ledger-checked
               rm/chmod, native `cp` (governed by `overwrite`, like
               `curl -o`/`wget -O`), GET fetches via an in-process,
               timeout- and redirect-bounded HTTP client (ureq) that
               refuses to downgrade an https:// fetch to plaintext on
               redirect, restricted-grammar rc-file appends, native
               SHA-256 compute/verify, direct fork/exec (never a shell)
               of the subprocess tier's literal argv, registering a
               function body for a later call, reporting a `test`/`[ ]`
               expression's already-computed result, and recording a
               `VAR=value` assignment in the session — and records
               created paths (and defined functions and variables) in
               the ledger. A second entry point,
               `execute_returning_status`, reports a `Subprocess`/`Test`
               outcome as a `bool` instead of an `Err`, for main.rs's
               `if`/`while`/`until` condition and `&&`/`||` command-list
               evaluation.
  prompt.rs    /dev/tty confirmation for `ask` verdicts (stdin carries
               the script); `--yes`/`--no` resolve asks without a tty
  broker.rs    (planned) privileged worker: `sudo iish --broker`,
               closed enum of operations over a socketpair (see
               "Privilege: the sudo broker")
  state.rs     Session ledger: paths created during this run — the
               source of truth for "may delete / may chmod / may run"
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
   assignment, a redirect shape beyond `>>` and `2> /dev/null`, a
   pipeline `!` negation, a special/positional parameter (`$@`, `$1`,
   ...), a richer parameter-expansion operator (`${VAR:-default}`,
   `${VAR#pattern}`, ...), or command substitution — none of which are
   implemented yet.
   The evaluator still denies `for`/`while`/`until` entirely, so none of
   the 17 real corpus scripts run to completion, but several now
   progress well past their own function/`set`/brace-group/`if`/`case`
   setup before stopping on one of those remaining gaps.
   `scripts/verify-installers.sh` (Docker-isolated,
   network-disabled, runnable in CI or by hand — see
   `.github/workflows/installer-verify.yml`) runs a curated,
   user-space-only subset of the corpus through the real binary and
   pins *why* each currently stops, as a regression guard: the pin
   breaking means either a regression or genuine milestone-7 progress,
   either way worth a human's attention. If/when a script ever runs to
   completion, the same harness checks the resulting program is
   actually usable, not just that iish didn't refuse. The same script
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
   `/bin` itself is a symlink to `usr/bin`. *(in progress — harness in place,
   functions/brace-groups/`set`/native `cp`/`if`/`case`/`test`/`&&`/`||`/
   bare assignment landed, corpus still 0/17 to completion)*
8. **Sandboxing investigation** — Landlock/seccomp/Seatbelt for second
   stages (post-first-iteration).
