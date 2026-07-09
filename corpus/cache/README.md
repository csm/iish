# Corpus cache

17 real-world `curl | sh` installer scripts, used by
`corpus/ANALYSIS.md` and (later) as an integration-test corpus. This
directory is git-tracked so sessions don't need network access just to
read or test against it — no more re-fetching every time.

**Last synced:** see [`FETCHED_AT`](./FETCHED_AT) (UTC date, written by
`corpus/fetch.sh`).

## Updating

```
corpus/fetch.sh           # fetch only scripts that are missing (e.g. a new entry)
corpus/fetch.sh --force   # re-download everything, picking up upstream changes
```

Either form rewrites `FETCHED_AT`. Review the diff before committing —
these are third-party scripts fetched over HTTPS from
raw.githubusercontent.com, and a real installer update should look
like one (small, plausible diffs), not something unexpected.

## Contents

rustup, nvm, homebrew, deno, oh-my-zsh, pnpm, volta, starship,
tailscale, docker, k3s, helm, nix (Determinate installer), ollama, rvm,
zoxide, atuin — see `corpus/fetch.sh` for exact source URLs.
