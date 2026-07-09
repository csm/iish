# Parser crate evaluation: brush-parser vs yash-syntax

Decision: **brush-parser**. Evaluated 2026-07-09 by parsing the full
17-script corpus (`corpus/fetch.sh`) with both candidates.

## Corpus parse coverage

| | brush-parser 0.4.0 | yash-syntax 0.21.0 |
|---|---|---|
| scripts parsed | **17/17** | 13/17 |
| failures | — | helm, homebrew, rvm, volta |

All four yash-syntax failures are `UnsupportedDoubleBracketCommand`:
yash targets POSIX and does not parse bash's `[[ ]]`, which 7/17
corpus scripts use (corpus/ANALYSIS.md §1). This alone is
disqualifying — helm, homebrew, rvm, and volta would be unrunnable.
(yash-syntax 0.23 was not testable — it requires Rust 1.96 — but the
crate's POSIX scope is by design, not an implementation gap.)

## License

- brush-parser: **MIT** — compatible with iish's MIT license.
- yash-syntax: **GPL-3.0-or-later** — would force relicensing iish.

Independently disqualifying.

## API / AST ergonomics (both are workable; brush notes)

- Sync API: `Parser::new(impl BufRead, &ParserOptions).parse_program()`
  → `ast::Program`. yash-syntax's parser is async under the hood
  (sync `FromStr` wrappers exist).
- AST covers the full grammar the corpus needs: pipelines, and-or
  lists, `if`/`case`/`for`/`while`, subshells, brace groups, function
  definitions, extended test (`[[ ]]`), redirects including heredocs
  and process substitution, arithmetic.
- `SimpleCommand` carries structured prefix/suffix items (assignments,
  redirects, words) — the natural hook for policy evaluation.
- Two-stage word model: AST words are unexpanded; `word::parse` turns
  a word into `WordPiece`s (text, quoting, tilde, parameter expansion,
  command substitution). Expansion is therefore evaluator-driven,
  which is exactly where iish's policy must sit. Command substitution
  pieces carry the inner source as a string, which iish re-parses and
  policy-checks recursively — the same mechanism already planned for
  `sudo sh -c '…'`.
- `ParserOptions` has posix/extended-test toggles; source spans are
  available for error reporting.

## Risks accepted

- brush-parser is pre-1.0 (0.4.0); API may churn. It is actively
  maintained as the parser of the brush shell, which tracks bash
  compatibility — incentives aligned with ours.
- Parse success ≠ evaluation support: iish's evaluator still decides,
  node by node, what it actually implements; everything else keeps the
  Unsupported→deny posture.
