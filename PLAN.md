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

Open policy questions to refine later:
- Running binaries the script just downloaded (many installers do a
  second-stage `./installer`): deny, prompt, or sandbox?
- Package-manager calls (`apt-get install`, `brew install`): prompt?
- Variable expansion / command substitution: which subset to support
  (`$(uname -s)` style probes are ubiquitous in installers).
- Control flow: `if`/`case` on platform detection is essentially
  mandatory to support real installers.

## Architecture

```
src/
  main.rs      CLI entry: read script (stdin or file), parse, plan, run
  parser.rs    bash → AST. Currently a minimal hand-rolled parser for
               simple commands; anything it can't parse becomes an
               explicit Unsupported node (which policy denies).
               May be replaced by a real bash-grammar crate
               (yash-syntax / brush-parser) once direction settles.
  policy.rs    AST node → Verdict { Allow, Prompt(reason), Deny(reason) }
  exec.rs      Native implementations of allowed operations
               (file writes, env-file appends, GET fetches, tracked rm)
  state.rs     Session ledger: paths created during this run — the
               source of truth for "may delete / may chmod"
```

Execution model: two-phase where possible — parse the whole script,
show the plan (what will be done, what is denied), then execute.
Scripts with data-dependent control flow will force some interleaving;
that's a refinement discussion.

## Milestones

1. **Scaffold (this commit)** — cargo project, module skeleton,
   parser for simple commands, policy stub, `--dry-run`-style report.
2. Real execution of the allowed set + session ledger + prompts.
3. Real bash grammar coverage (quoting, `&&`/`||`, `if`, variables,
   command substitution subset).
4. Harden: redirect handling, env-file grammar, HTTP GET client.
5. Test corpus of real-world install scripts (rustup, nvm, brew, …).
