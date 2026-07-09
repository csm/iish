# Installer corpus analysis

Empirical survey of 17 real-world `curl | sh` installer scripts
(~10,200 lines total), fetched 2026-07-09 via `corpus/fetch.sh`:
rustup, nvm, homebrew, deno, oh-my-zsh, pnpm, volta, starship,
tailscale, docker, k3s, helm, nix (Determinate installer), ollama,
rvm, zoxide, atuin.

## 1. Shell grammar: the minimal parser is not viable

Constructs by number of scripts using them (out of 17):

| Construct | Scripts | Construct | Scripts |
|---|---|---|---|
| functions | 17 | `set -e`/`-u` | 13 |
| `if` | 17 | `local` | 9 |
| `case` | 17 | `${VAR#%/}` trims | 9 |
| `for`/`while` | 17 | `[[ ]]` | 7 |
| `$(...)` substitution | 17 | `read` (user input) | 7 |
| `${VAR:-default}` | 16 | heredocs | 5 |
| pipes | 15 | `trap` | 5 |
| backtick substitution | 14 | subshells | 5 |
| | | `eval` | 4 |

**Implication:** every script needs functions, conditionals, loops,
command substitution, and parameter expansion. A near-complete POSIX
shell grammar (plus a few bashisms like `[[ ]]`) is table stakes, so
the hand-rolled parser gets replaced by a real shell-grammar crate
(candidates: `yash-syntax`, `brush-parser`) with iish's policy applied
at the point of command execution, not at parse time.

`eval` is rarer and mostly avoidable (homebrew uses it for
`brew shellenv`, nvm for building a wget command line); deny by
default, likely forever.

## 2. Execution must interleave (confirmed)

14/17 probe the platform with `uname`, 16/17 probe for tools with
`command -v`/`which`, and all branch on the results — download URLs,
install dirs, and package-manager choice are all runtime-dependent.
A static plan-then-run phase split cannot work; iish walks the AST and
consults policy at each command execution.

## 3. External commands: the empirical allowlist tiers

Commands by number of scripts invoking them (word-boundary grep;
prose mentions inflate common words slightly — treat as upper bounds):

- **Read-only probes / text processing** — `command` 16, `uname` 14,
  `which` 14, `grep` 14, `printf` 14, `echo` 17, `cut` 9, `cat` 9,
  `sed` 8, `tail` 8, `head` 7, `awk` 7, `tr` 6, `id` 6, `type` 5,
  `basename`/`dirname` 3, `sort` 3, `tput` 2, `getconf` 2.
  → Safe to **allow** by default: no filesystem writes, no network.
  (`sed -i` is the exception; that's a file write and is mediated.)
- **Filesystem mutation** — `mkdir` 13, `chmod` 10, `rm` 9,
  `mktemp` 9, `tar` 6, `unzip` 6, `tee` 5, `touch` 4, `mv` 3,
  `install` (real invocations present, count inflated), `cp` 2,
  `ln` 2, `chown` 2.
  → Implemented **natively** with ledger checks: create-only writes,
  overwrite ⇒ prompt, delete/chmod only ledger-owned paths. `mktemp`
  results are recorded as owned. `chown` ⇒ ask.
- **Network** — `curl` 17, `wget` 9, `openssl` 3 (checksums), `git` 2
  (clone; nvm and oh-my-zsh install *via* git clone).
  → GET-only native fetch as planned. `git clone` into a new
  directory is worth supporting (ask by default).
- **Privilege / system mutation** — `sudo` 10(!), package managers
  (`apt-get`/`dnf`/`yum`/`zypper`/`pacman`/`apk`/`brew`) 5,
  `systemctl` 4.
  → Cannot be blanket-denied without breaking the majority of the
  corpus. Default **ask**, configurable.

## 4. Behavior patterns

| Pattern | Scripts | Notes |
|---|---|---|
| platform detection (`uname`) | 14/17 | |
| `mktemp` staging dir | 10/17 | ledger ownership covers children |
| `sudo`/root escalation | 10/17 | biggest policy tension |
| writes under `/usr/local` or `/opt` | 6/17 | usually behind sudo |
| GPG/checksum verification | 7/17 | iish could do this natively |
| modifies rc/profile files | 5/17 | atuin, homebrew, nvm, oh-my-zsh, starship |
| invokes package manager | 5/17 | |
| systemd unit install/start | 4/17 | docker, k3s, ollama, tailscale |
| runs downloaded second stage | ≥4/17 | rustup, volta, deno, rvm: download → `chmod +x` → run |
| interactive prompts | 7/17 | via `/dev/tty`, since stdin is the script |

Notable specifics:

- **Second stage:** rustup downloads `rustup-init`, `chmod u+x`, runs
  it (with stdin re-pointed at `/dev/tty`), then `rm`s it. Policy
  needs a story for "execute a file this script just created" —
  default **ask**, showing provenance (URL it came from).
- **`/dev/tty`:** scripts that prompt already read from `/dev/tty`
  because stdin is the pipe. iish must do the same for its own
  prompts, and provide `/dev/tty` to `read` when interleaving.
- **rc-file edits** are appends of `export`, `PATH=`, `source`/`eval`
  shellenv lines — matching the planned restricted append grammar.

## 5. Consequences for iish

1. Replace the hand-rolled parser with a real shell grammar crate;
   keep the Unsupported→deny posture for anything the crate can't
   parse or iish can't evaluate.
2. Interleaved evaluation (decided).
3. Policy verbs are **allow / ask / deny** per command or category,
   with config-file defaults and CLI overrides — `ask` is load-bearing
   because sudo, package managers, and second-stage execution are too
   common to deny and too dangerous to allow.
4. Native value-adds fall out for free: GET-only fetching, checksum
   verification, ledger-tracked temp dirs, restricted rc-appends.

## 6. What sudo is actually used for

Categorizing every `sudo`/`$SUDO`/`$sh_c` invocation across the 10
scripts that escalate:

1. **Root file operations** — the most frequent bucket: `sudo tee` of
   apt source lists (tailscale) and systemd unit files (k3s),
   `sudo mkdir -p`, `sudo chmod/chown/chgrp` (homebrew does this in
   bulk), `sudo cp`. All of these are operations iish already mediates
   natively for the unprivileged case.
2. **sudo bookkeeping** — `sudo -v`, `sudo -n -v` credential checks,
   probes for sudo/doas existence, `id -u` root tests.
3. **External root binaries** — `systemctl enable/daemon-reload`
   (docker, k3s, ollama, tailscale), package managers
   (`apt-get`/`dnf`/`yum` update+install), `gpg --import` (rvm),
   `xcode-select`/`xcodebuild -license` (homebrew), `lshw` (ollama).
4. **`sudo sh -c '…'`** — docker wraps *every* mutating command in
   `sh_c='sudo -E sh -c'`; k3s and tailscale use `$SUDO sh -c` for
   redirection-as-root.

**Implication (adopted in PLAN.md):** buckets 1–2 are fully coverable
by a privileged iish broker executing the same native, ledger-checked
operations as the unprivileged path; bucket 4 becomes transparent by
recursively parsing the `sh -c` string; bucket 3 remains `ask` but
gains fixed-argv, sanitized-env execution with no shell in between.
