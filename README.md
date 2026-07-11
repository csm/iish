# iish

A shell for installing things in that way
the kids came up with: fetching something
from a URL and piping it to a shell.

## Capability analysis

Use `iish --analyze install.sh` to inventory what an installer needs without
executing it. The analyzer uses the same Bash parser and policy evaluator as a
real iish run, but conservatively visits every arm of `if`/`elif`/`else`, every
stage of `&&`/`||` and pipelines, and one representative pass through loop
bodies. Each leaf reports:

- its branch guard, with best-effort Windows, macOS, or Linux annotation;
- the required capability (for example `filesystem.mkdir`, `network.http_get`,
  or `process.exec(tar)`);
- whether iish supports it natively, supports it through the configurable
  subprocess/confirmation tier, or refuses it because support is missing.

Platform annotations never suppress a branch. They are hints so a human or
coding agent can deliberately exclude an irrelevant target. Conditions and
loop counts that depend on command output remain symbolic because analysis
runs no commands; command substitutions are consequently reported as missing
static information rather than guessed.

```console
$ iish --analyze install.sh
iish capability analysis (1 top-level statement(s)):
  All branches are scanned statically; no commands are executed.
  [IF    ] if test "$OS" = Linux; then mkdir -p "$HOME/.tool"; fi
           condition: test "$OS" = Linux [platform: Linux]
    [ALLOW ] test "$OS" = Linux
             requires: builtin.control/test (native)
           then (when condition succeeds):
    [ALLOW ] mkdir -p "$HOME/.tool"
             requires: filesystem.mkdir (native)
```
