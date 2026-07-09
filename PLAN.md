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
| sudo | Not a command — an **execution context**. See "Privilege: the sudo broker" below |
| Shells (`sh`/`bash`/`zsh`/`dash`/`ksh`), shell builtins (`cd`, `export`, `source`, `.`), pipelines, control flow, `eval` | Denied — no config knob reopens these; see "Core principle" |
| Everything else — external binaries iish has no native implementation for (`cp`, `tar`, `apt-get`, `systemctl`, `sudo <cmd>` pre-broker, …) | **ask** by default (the "subprocess" tier); allow/ask/deny, globally or per command, in config — see "Configuration" |

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

`subprocess`, `overwrite`, `network`, `run-created`, and `[commands]` are
live: they change what policy.rs's evaluator does today, including a
new **subprocess tier** for any external binary iish has no native
implementation for (`cp`, `tar`, `apt-get`, `sudo <cmd>` pre-broker,
…) — the literal, already-parsed argv is exec'd directly, never through
a shell, once allowed or confirmed. Shells and shell builtins (`cd`,
`export`, `source`, `.`) stay hard-denied regardless of config — see the
"Core principle" above. `env-file-append` and `elevate` parse
successfully (so this file round-trips) but aren't consulted until
milestone 6 (env-file grammar) and 4b (sudo broker) exist.

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
               literal string when it needs no expansion.
  policy.rs    The evaluator: walks `parser::ast` node by node and
               produces a Verdict { Allow, Prompt(reason), Deny(reason) }
               per top-level statement. Anything not yet implemented
               (pipelines, control flow, functions, redirects,
               expansions, ...) is denied here — the Unsupported→deny
               posture now lives in the evaluator, not the parser.
  config.rs    Layered policy (milestone 5): builtin `Config::default()`
               ← config file (TOML via serde) ← CLI overrides. Exposes
               `Verb` (allow/ask/deny) and `NetworkPolicy` per PLAN's
               sketch below; unconsumed knobs (`env-file-append`,
               `elevate`) still parse, for forward compatibility with
               the documented schema.
  exec.rs      Native implementations of allowed operations. The policy
               compiles each allowed statement into a closed `Action`
               enum (Print, MkDir, Remove, Chmod, Fetch, Subprocess,
               Noop); exec runs actions in Rust — echo/printf
               rendering, dir creation, ledger-checked rm/chmod, GET
               fetches via an in-process HTTP client (ureq), and
               direct fork/exec (never a shell) of the subprocess
               tier's literal argv — and records created paths in the
               ledger. Env-file appends land in milestone 6.
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
6. **Harden** — redirects, env-file append grammar, GET-only HTTP
   client, checksum verification.
7. **Corpus as test suite** — iish should run the majority of the
   corpus to completion (with expected asks).
8. **Sandboxing investigation** — Landlock/seccomp/Seatbelt for second
   stages (post-first-iteration).
