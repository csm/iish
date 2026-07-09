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
| chmod / chown | `chmod` allowed on files the script created; `chown`/`sudo` denied |
| Everything else (eval, exec, arbitrary binaries, pipes to sh, …) | Denied |

Policy verbs are **allow / ask / deny**. `ask` is load-bearing: the
corpus shows sudo (10/17), package managers, systemctl, and running a
just-downloaded second stage are too common to deny outright and too
consequential to allow silently (see `corpus/ANALYSIS.md`).

## Configuration

Layered policy, later layers win:

1. Built-in defaults (the table above; unlisted subprocesses ⇒ ask).
2. User config file (`~/.config/iish/config.toml`).
3. Command-line overrides.

Sketch:

```toml
[defaults]
subprocess = "ask"        # unlisted external commands: allow|ask|deny
overwrite = "ask"         # writing over pre-existing files
env-file-append = "ask"   # rc/profile appends (restricted grammar)
run-created = "ask"       # executing files the script created
network = "get-only"      # get-only|deny

[commands]                # per-command overrides
sudo = "deny"
"apt-get" = "ask"
uname = "allow"
```

CLI: `iish --allow sudo --deny curl --subprocess=deny --dry-run …`,
plus `--yes`/`--no` to resolve every `ask` non-interactively.

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
  parser.rs    bash → AST. Currently a minimal hand-rolled parser for
               simple commands; anything it can't parse becomes an
               explicit Unsupported node (which policy denies).
               To be replaced by a real shell-grammar crate
               (yash-syntax / brush-parser): the corpus shows 17/17
               scripts need functions, conditionals, loops, and
               command substitution (see corpus/ANALYSIS.md §1).
  policy.rs    command → Verdict { Allow, Ask(reason), Deny(reason) }
  config.rs    (planned) layered policy: builtins ← config file ← CLI
  exec.rs      Native implementations of allowed operations
               (file writes, env-file appends, GET fetches, tracked rm)
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
nvm, docker, k3s, nix, …) into `corpus/cache/` (not committed).
Findings that drive the design are in `corpus/ANALYSIS.md`. The cache
doubles as the integration-test corpus later.

## Milestones

1. ~~**Scaffold**~~ — cargo project, module skeleton, minimal parser,
   policy stub, report mode. *(done)*
2. ~~**Corpus**~~ — fetch + empirical analysis of real installers.
   *(done — see corpus/ANALYSIS.md)*
3. **Real parser** — adopt a shell-grammar crate, walk its AST with an
   interleaved evaluator; Unsupported→deny posture preserved.
4. **Execution + ledger** — native implementations of the allowed
   tiers, session ledger, `/dev/tty` prompting.
5. **Configuration** — config-file policy + CLI overrides (see below).
6. **Harden** — redirects, env-file append grammar, GET-only HTTP
   client, checksum verification.
7. **Corpus as test suite** — iish should run the majority of the
   corpus to completion (with expected asks).
8. **Sandboxing investigation** — Landlock/seccomp/Seatbelt for second
   stages (post-first-iteration).
