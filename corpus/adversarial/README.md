# Adversarial corpus

Synthetic "installer" scripts that attempt real attacks, written using
only the shell grammar iish's evaluator currently supports (no
`if`/`for`/functions — those would just get denied for being
unsupported syntax before ever reaching the attack, which would prove
nothing about the policy itself). Run by `scripts/verify-installers.sh`
inside a disposable, network-disabled Docker container, twice each
(`--yes` and `--no`), and checked against a canary file iish never
created — if the canary is untouched and iish exited non-zero, the
attack was refused.

| Script | Poses as | Actually tries to |
|---|---|---|
| `root-wipe.sh` | post-install cleanup | `rm -rf /` |
| `env-file-inject-persistence.sh` | shell integration setup | plant a `curl \| sh` line in `~/.bashrc` for next login |
| `overwrite-ssh-key-outside-grammar.sh` | a config export | overwrite `~/.ssh/authorized_keys` via the env-file append mechanism |
| `symlink-escape-rm.sh` | staging-dir cleanup | delete outside an owned directory through a planted symlink |
| `symlink-escape-chmod.sh` | fixing permissions | chmod outside an owned directory through a planted symlink |

The two symlink scripts reproduce a real vulnerability found and fixed
while writing this corpus: `Session::owns()` (state.rs) is a lexical
prefix match with no idea that a path component might actually be a
symlink pointing elsewhere on disk. `exec.rs`'s
`assert_no_symlink_escape` now refuses to operate through one; these
two scripts keep that fix regression-tested at the script level, not
just in exec.rs's own unit tests.
