//! Bash parsing, delegated to brush-parser (see docs/parser-eval.md),
//! plus iish's word-expansion machinery.
//!
//! iish does not implement bash grammar itself. This module hands the
//! script to brush-parser and returns its AST, or a top-level syntax
//! error. Deciding what iish actually understands and is willing to run
//! is the evaluator's job (`policy.rs`): it walks that AST and denies
//! whatever construct it doesn't implement, node by node. That is the
//! same "if we didn't understand it, we don't run it" posture the old
//! hand-rolled parser used to enforce directly, just moved one layer up
//! now that parsing itself covers the full grammar.
//!
//! Word expansion happens here too, against an [`ExpandCtx`]: the live
//! session (variables, call frames, `$?`) plus a [`Substituter`] that
//! can run a `$(command)` and capture its output — the runner (main.rs)
//! provides the real one, `--dry-run` and unit tests one that refuses.

use crate::state::Session;

pub use brush_parser::ast;
pub use brush_parser::word::WordPiece;
use brush_parser::word::{Parameter, ParameterExpr, ParameterTestType, SpecialParameter};

/// Runs the command text inside a `$(...)`/backquote substitution and
/// returns its captured stdout (before bash's trailing-newline
/// stripping, which the caller here applies). The real implementation
/// lives in main.rs, where the full runner — policy, prompts, native
/// execution — is available to interpret the inner script; it may
/// mutate `session` exactly like any other statements it runs.
pub trait Substituter {
    fn substitute(&mut self, session: &mut Session, command: &str) -> Result<String, String>;
}

/// A [`Substituter`] for contexts where no command may run: `--dry-run`
/// (which executes nothing, so a substitution's output is unknowable)
/// and unit tests. Every substitution fails with the given reason,
/// which becomes the enclosing statement's deny reason.
pub struct RefuseSubstituter(pub &'static str);

impl Substituter for RefuseSubstituter {
    fn substitute(&mut self, _session: &mut Session, _command: &str) -> Result<String, String> {
        Err(self.0.to_string())
    }
}

/// Everything word expansion may consult: the live session (variables,
/// call frames, `$?`, the ledger) and a way to run `$(command)`
/// substitutions. Mutable because a substitution really runs — it may
/// assign variables, create files, or anything else its statements are
/// allowed to do — and `${VAR:=default}` assigns too.
pub struct ExpandCtx<'a> {
    pub session: &'a mut Session,
    pub subst: &'a mut dyn Substituter,
}

/// Shell-identity variables iish answers for even though its own
/// process environment doesn't have them: scripts probe these to learn
/// what shell is interpreting them. iish executes the bash dialect
/// (brush-parser's grammar) with POSIX-style semantics, so it
/// identifies as a bash in POSIX mode — the version string is
/// deliberately shaped like bash's with an `iish` suffix, and
/// `POSIXLY_CORRECT` answers as set (starship's "please use a POSIX
/// shell" guard accepts exactly this pair). `ZSH_VERSION` is left
/// genuinely unset: a `${ZSH_VERSION+x}` set-test must say "not zsh".
fn shell_identity(name: &str) -> Option<&'static str> {
    match name {
        "BASH_VERSION" => Some("5.2.0(1)-iish"),
        "POSIXLY_CORRECT" => Some("1"),
        _ => None,
    }
}

/// Parser options shared across script and word parsing.
fn options() -> brush_parser::ParserOptions {
    brush_parser::ParserOptions::default()
}

/// Parse a whole script into brush-parser's AST.
pub fn parse(script: &str) -> Result<ast::Program, String> {
    let mut parser = brush_parser::Parser::new(script.as_bytes(), &options());
    parser.parse_program().map_err(|e| e.to_string())
}

fn parse_word_pieces(
    word_text: &str,
) -> Result<Vec<brush_parser::word::WordPieceWithSource>, String> {
    brush_parser::word::parse(word_text, &options())
        .map_err(|e| format!("could not parse word `{word_text}`: {e}"))
}

/// Render a shell [`ast::Word`] to a single literal string. Anything the
/// expansion machinery here doesn't cover — most parameter-expansion
/// operators, array/most special parameters, ANSI-C quoting, unquoted
/// globbing — is rejected with a reason instead of being guessed at.
/// `$@`/`$*` in this scalar context join the positional parameters with
/// single spaces (callers that care about argument boundaries — command
/// arguments, `for` lists — use [`word_fields`] instead).
pub fn literal_word(word: &ast::Word, ctx: &mut ExpandCtx) -> Result<String, String> {
    render_word_text(&word.value, ctx)
}

/// [`literal_word`] over raw word source text (used for a parameter
/// expansion's embedded default value, e.g. the `${HOME}` inside
/// `${ZDOTDIR:-${HOME}}`, which brush keeps as unparsed text).
fn render_word_text(text: &str, ctx: &mut ExpandCtx) -> Result<String, String> {
    let pieces = parse_word_pieces(text)?;
    let mut out = String::new();
    for piece in &pieces {
        push_literal_piece(&piece.piece, &mut out, true, ctx)?;
    }
    Ok(out)
}

/// Expand a shell [`ast::Word`] to the list of argument fields it
/// produces — bash's real unit for command arguments and `for` lists,
/// where one word can become zero, one, or many arguments:
///
/// * `"$@"` (and unquoted `$@`/`$*`) expands to one field per
///   positional parameter — zero fields when there are none — so
///   `main "$@"` forwards argument boundaries intact;
/// * a word that is exactly one unquoted `$VAR` or `$(cmd)` is
///   whitespace-split after expansion (and an empty value disappears
///   entirely), matching bash's IFS field splitting for the shapes
///   installers actually rely on (`for f in $FILES`, `curl $FLAGS ...`);
/// * everything else renders to exactly one field via [`literal_word`]'s
///   rules (quoted text never splits).
pub fn word_fields(word: &ast::Word, ctx: &mut ExpandCtx) -> Result<Vec<String>, String> {
    let pieces = parse_word_pieces(&word.value)?;

    // A word that is exactly `$@`/`$*`, possibly double-quoted.
    if let [only] = pieces.as_slice() {
        let unquoted_expr = match &only.piece {
            WordPiece::ParameterExpansion(expr) => Some((expr, true)),
            WordPiece::DoubleQuotedSequence(inner) => match inner.as_slice() {
                [one] => match &one.piece {
                    WordPiece::ParameterExpansion(expr) => Some((expr, false)),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        if let Some((
            ParameterExpr::Parameter {
                parameter:
                    Parameter::Special(SpecialParameter::AllPositionalParameters { concatenate }),
                indirect: false,
            },
            unquoted,
        )) = unquoted_expr
        {
            // `"$*"` is the one shape that joins instead of splitting.
            if *concatenate && !unquoted {
                return Ok(vec![ctx.session.positional().join(" ")]);
            }
            return Ok(ctx.session.positional().to_vec());
        }

        // A lone unquoted `$VAR` or `$(cmd)`: expand, then field-split.
        let expanded = match &only.piece {
            WordPiece::ParameterExpansion(expr) => Some(resolve_parameter_expansion(expr, ctx)?),
            WordPiece::CommandSubstitution(cmd) | WordPiece::BackquotedCommandSubstitution(cmd) => {
                Some(run_substitution(cmd, ctx)?)
            }
            _ => None,
        };
        if let Some(value) = expanded {
            return Ok(value.split_whitespace().map(str::to_string).collect());
        }
    }

    // General case: render the word to a glob *pattern* (unquoted `*`/`?`
    // from the script's own text stay wildcards; quoted text, escapes,
    // and — deliberately — the values of any expansion are `\`-escaped
    // so runtime data can never smuggle in a wildcard). If the pattern
    // has an active wildcard that matches paths on disk, expand to the
    // sorted matches (bash pathname expansion); if it matches nothing,
    // the literal pattern stands (nullglob off); with no wildcard at all
    // it's just the literal word.
    let pattern = render_pattern_text(&word.value, ctx)?;
    if pattern_has_active_wildcard(&pattern) {
        let matches = glob_expand(&pattern);
        if !matches.is_empty() {
            return Ok(matches);
        }
    }
    Ok(vec![unescape_pattern(&pattern)])
}

/// True if `s` contains a character that would undergo bash pathname
/// expansion left un-quoted: `*`/`?` always, and `[` only when it's
/// actually the opening half of a bracket expression (paired with a
/// later `]`) — a lone `[` (the `[` test command; a filename that just
/// happens to contain one) glob-expands to itself, so it isn't rejected
/// as "globbing" here.
fn contains_glob_metachar(s: &str) -> bool {
    if s.contains(['*', '?']) {
        return true;
    }
    match s.find('[') {
        Some(open) => s[open + 1..].contains(']'),
        None => false,
    }
}

/// Run one `$(command)` substitution and apply bash's trailing-newline
/// stripping to what it captured.
fn run_substitution(command: &str, ctx: &mut ExpandCtx) -> Result<String, String> {
    let mut output = ctx.subst.substitute(ctx.session, command)?;
    while output.ends_with('\n') {
        output.pop();
    }
    Ok(output)
}

/// Append one word piece's literal text to `out`, or fail with the reason
/// it can't be rendered without expansion. `unquoted` is true for pieces
/// that sit directly in the word (where bash would still glob-expand
/// `*`/`?`/`[`) and false for pieces nested inside double quotes (where
/// those characters are already literal).
fn push_literal_piece(
    piece: &WordPiece,
    out: &mut String,
    unquoted: bool,
    ctx: &mut ExpandCtx,
) -> Result<(), String> {
    match piece {
        WordPiece::Text(s) => {
            if unquoted && contains_glob_metachar(s) {
                return Err("globbing is not supported yet".into());
            }
            out.push_str(s);
            Ok(())
        }
        WordPiece::SingleQuotedText(s) => {
            out.push_str(s);
            Ok(())
        }
        WordPiece::EscapeSequence(s) => {
            // Always a backslash followed by exactly the escaped character.
            out.push_str(&s[1..]);
            Ok(())
        }
        WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
            for p in inner {
                push_literal_piece(&p.piece, out, false, ctx)?;
            }
            Ok(())
        }
        WordPiece::AnsiCQuotedText(_) => Err("ANSI-C quoting ($'...') is not supported yet".into()),
        WordPiece::TildeExpansion(brush_parser::word::TildeExpr::Home) => {
            match std::env::var("HOME") {
                Ok(home) => {
                    out.push_str(&home);
                    Ok(())
                }
                Err(_) => Err("cannot expand `~`: $HOME is not set".into()),
            }
        }
        WordPiece::TildeExpansion(_) => {
            Err("tilde expansion is only supported for `~` (the home directory)".into())
        }
        WordPiece::ParameterExpansion(expr) => {
            out.push_str(&resolve_parameter_expansion(expr, ctx)?);
            Ok(())
        }
        WordPiece::CommandSubstitution(cmd) | WordPiece::BackquotedCommandSubstitution(cmd) => {
            out.push_str(&run_substitution(cmd, ctx)?);
            Ok(())
        }
        WordPiece::ArithmeticExpression(_) => {
            Err("arithmetic expansion is not supported yet".into())
        }
    }
}

/// The value of `parameter` right now, or `None` if it's genuinely
/// unset (what the `${VAR:-default}` family branches on). Named
/// variables resolve through the session's call frames and globals
/// first (an assignment always shadows the environment, as in bash),
/// then the real process environment, then the shell-identity table.
fn resolve_parameter(parameter: &Parameter, ctx: &ExpandCtx) -> Result<Option<String>, String> {
    match parameter {
        Parameter::Named(name) => Ok(ctx
            .session
            .get_variable(name)
            .map(str::to_string)
            .or_else(|| std::env::var(name).ok())
            .or_else(|| shell_identity(name).map(str::to_string))),
        Parameter::Positional(0) => Ok(Some(ctx.session.script_name().to_string())),
        Parameter::Positional(n) => Ok(ctx.session.positional().get((*n - 1) as usize).cloned()),
        Parameter::Special(special) => match special {
            SpecialParameter::AllPositionalParameters { .. } => {
                // In a scalar context both `$@` and `$*` join with
                // spaces; argument-boundary-preserving `"$@"` lives in
                // `word_fields`.
                Ok(Some(ctx.session.positional().join(" ")))
            }
            SpecialParameter::PositionalParameterCount => {
                Ok(Some(ctx.session.positional().len().to_string()))
            }
            SpecialParameter::LastExitStatus => Ok(Some(ctx.session.last_status().to_string())),
            SpecialParameter::ProcessId => Ok(Some(std::process::id().to_string())),
            SpecialParameter::ShellName => Ok(Some(ctx.session.script_name().to_string())),
            SpecialParameter::CurrentOptionFlags => {
                Err("`$-` (current option flags) is not supported yet".into())
            }
            SpecialParameter::LastBackgroundProcessId => {
                Err("`$!` is not supported: background jobs are not implemented".into())
            }
        },
        Parameter::NamedWithIndex { .. } | Parameter::NamedWithAllIndices { .. } => {
            Err("array variable expansion is not supported yet".into())
        }
    }
}

fn describe_parameter(parameter: &Parameter) -> String {
    match parameter {
        Parameter::Named(name) => format!("${name}"),
        Parameter::Positional(n) => format!("${n}"),
        other => format!("{other:?}"),
    }
}

/// Is a resolved value "missing" for this test type? `${VAR-x}`
/// (`Unset`) only treats a genuinely unset variable as missing;
/// `${VAR:-x}` (`UnsetOrNull`) treats an empty value as missing too.
fn is_missing(value: &Option<String>, test_type: &ParameterTestType) -> bool {
    match test_type {
        ParameterTestType::Unset => value.is_none(),
        ParameterTestType::UnsetOrNull => value.as_deref().map(str::is_empty).unwrap_or(true),
    }
}

/// Resolve a parameter expansion to its literal text: plain
/// `$VAR`/`${VAR}` references, positional (`$1`, ...) and the common
/// special parameters (`$?`, `$#`, `$@`, `$*`, `$$`, `$0`), the
/// default/alternative-value operators (`${VAR:-x}`, `${VAR-x}`,
/// `${VAR:=x}`, `${VAR:+x}`), and `${#VAR}` length. The rest — pattern
/// removal (`${VAR#x}`, `${VAR%x}`), substrings, case modification,
/// indirection, arrays — is rejected with a reason.
///
/// A plain reference to an outright-unset name expands to empty (bash's
/// default) unless the script itself said `set -u`, in which case it is
/// rejected; the default-value operators are bash's own explicit way of
/// saying "unset is fine here", so they behave normally either way.
fn resolve_parameter_expansion(
    expr: &ParameterExpr,
    ctx: &mut ExpandCtx,
) -> Result<String, String> {
    if let ParameterExpr::Parameter { indirect: true, .. }
    | ParameterExpr::UseDefaultValues { indirect: true, .. }
    | ParameterExpr::AssignDefaultValues { indirect: true, .. }
    | ParameterExpr::UseAlternativeValue { indirect: true, .. } = expr
    {
        return Err("indirect parameter expansion (`${!VAR}`) is not supported yet".into());
    }
    match expr {
        ParameterExpr::Parameter { parameter, .. } => {
            match resolve_parameter(parameter, ctx)? {
                Some(value) => Ok(value),
                // Unless the script asked for `set -u`, an unset
                // variable expands to empty exactly as bash's would.
                None if !ctx.session.nounset() => Ok(String::new()),
                None => Err(format!("`{}` is unset", describe_parameter(parameter))),
            }
        }
        ParameterExpr::UseDefaultValues {
            parameter,
            test_type,
            default_value,
            ..
        } => {
            let value = resolve_parameter(parameter, ctx)?;
            if is_missing(&value, test_type) {
                match default_value {
                    Some(default) => render_word_text(default, ctx),
                    None => Ok(String::new()),
                }
            } else {
                Ok(value.unwrap_or_default())
            }
        }
        ParameterExpr::AssignDefaultValues {
            parameter,
            test_type,
            default_value,
            ..
        } => {
            let value = resolve_parameter(parameter, ctx)?;
            if is_missing(&value, test_type) {
                let default = match default_value {
                    Some(default) => render_word_text(default, ctx)?,
                    None => String::new(),
                };
                let Parameter::Named(name) = parameter else {
                    return Err(
                        "`${PARAM:=default}` assignment is only supported for named variables"
                            .into(),
                    );
                };
                ctx.session.set_variable(name.clone(), default.clone());
                Ok(default)
            } else {
                Ok(value.unwrap_or_default())
            }
        }
        ParameterExpr::UseAlternativeValue {
            parameter,
            test_type,
            alternative_value,
            ..
        } => {
            let value = resolve_parameter(parameter, ctx)?;
            if is_missing(&value, test_type) {
                Ok(String::new())
            } else {
                match alternative_value {
                    Some(alternative) => render_word_text(alternative, ctx),
                    None => Ok(String::new()),
                }
            }
        }
        ParameterExpr::ParameterLength { parameter, .. } => {
            match resolve_parameter(parameter, ctx)? {
                Some(value) => Ok(value.chars().count().to_string()),
                None if !ctx.session.nounset() => Ok("0".to_string()),
                None => Err(format!("`{}` is unset", describe_parameter(parameter))),
            }
        }
        ParameterExpr::RemoveSmallestSuffixPattern {
            parameter, pattern, ..
        } => remove_pattern(parameter, pattern.as_deref(), false, true, ctx),
        ParameterExpr::RemoveLargestSuffixPattern {
            parameter, pattern, ..
        } => remove_pattern(parameter, pattern.as_deref(), false, false, ctx),
        ParameterExpr::RemoveSmallestPrefixPattern {
            parameter, pattern, ..
        } => remove_pattern(parameter, pattern.as_deref(), true, true, ctx),
        ParameterExpr::RemoveLargestPrefixPattern {
            parameter, pattern, ..
        } => remove_pattern(parameter, pattern.as_deref(), true, false, ctx),
        _ => Err(
            "this form of parameter expansion (`${VAR/x/y}`, `${VAR:1:2}`, \
             `${VAR^^}`, ...) is not supported yet"
                .into(),
        ),
    }
}

/// `${VAR#pat}` / `${VAR##pat}` / `${VAR%pat}` / `${VAR%%pat}`: strip
/// the smallest/largest prefix/suffix of the parameter's value matching
/// the glob `pat`. The pattern text is itself expanded (quotes keep
/// wildcards literal, `$VAR`s resolve) with the same rules as a `case`
/// pattern, then matched with the same `*`/`?` glob matcher.
fn remove_pattern(
    parameter: &Parameter,
    pattern: Option<&str>,
    prefix: bool,
    smallest: bool,
    ctx: &mut ExpandCtx,
) -> Result<String, String> {
    let value = match resolve_parameter(parameter, ctx)? {
        Some(value) => value,
        None if !ctx.session.nounset() => String::new(),
        None => return Err(format!("`{}` is unset", describe_parameter(parameter))),
    };
    let rendered_pattern = match pattern {
        Some(text) => render_pattern_text(text, ctx)?,
        None => String::new(),
    };
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    // Candidate removal lengths, ordered so the first match wins as
    // the smallest (or largest) removal.
    let lengths: Vec<usize> = if smallest {
        (0..=n).collect()
    } else {
        (0..=n).rev().collect()
    };
    for len in lengths {
        let (removed, kept): (String, String) = if prefix {
            (chars[..len].iter().collect(), chars[len..].iter().collect())
        } else {
            (
                chars[n - len..].iter().collect(),
                chars[..n - len].iter().collect(),
            )
        };
        if glob_match(&rendered_pattern, &removed) {
            return Ok(kept);
        }
    }
    Ok(value)
}

/// Minimal glob matching shared by `case` patterns and
/// `${VAR#pattern}`-style removal: `*` matches any run of characters
/// (including none), `?` matches exactly one, `\x` matches the literal
/// character `x` (how a pattern character that came from quoted or
/// escaped source text — or from an expansion's value — is
/// represented, so it isn't treated as a wildcard even though it looks
/// like one), and any other character matches itself. No
/// bracket-expression (`[...]`) support: installers' patterns in
/// practice only ever reach for `*`/`?` (`Linux*`, `x86_64`, `*=`, a
/// bare `*` default, ...).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn matches(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| matches(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && matches(&p[1..], &t[1..]),
            Some('\\') if p.len() > 1 => !t.is_empty() && p[1] == t[0] && matches(&p[2..], &t[1..]),
            Some(c) => !t.is_empty() && *c == t[0] && matches(&p[1..], &t[1..]),
        }
    }
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    matches(&pattern_chars, &text_chars)
}

/// True if `pattern` (rendered by `render_pattern_text`, so literal
/// metacharacters are `\`-escaped) contains a wildcard that is still
/// active — an unescaped `*` or `?`. Bracket classes aren't treated as
/// active: `glob_match` doesn't implement them, so a `[...]` word is
/// left literal rather than half-expanded.
fn pattern_has_active_wildcard(pattern: &str) -> bool {
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '*' | '?' => return true,
            _ => {}
        }
    }
    false
}

/// Turn a rendered glob pattern back into its literal text by dropping
/// the `\` before each escaped character — the value a word takes when
/// its wildcards matched nothing (nullglob off) or it had none.
fn unescape_pattern(pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Bash pathname expansion for a rendered glob `pattern`: walk it one
/// `/`-separated component at a time, descending literal components and
/// matching wildcard components against real directory entries
/// (`glob_match`), and return every existing path that matches, sorted.
/// A leading-dot entry is matched only by a pattern whose component
/// starts with a literal dot, as in bash. An empty result means "no
/// match" and the caller keeps the literal pattern.
fn glob_expand(pattern: &str) -> Vec<String> {
    use std::path::PathBuf;
    let absolute = pattern.starts_with('/');
    // Split on unescaped `/`. A `\/` never occurs here (paths don't
    // escape their separators), so a plain split is correct.
    let components: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Vec::new();
    }

    // Each frontier entry is (filesystem path to read from, display
    // prefix accumulated so far).
    let start = if absolute {
        (PathBuf::from("/"), String::from("/"))
    } else {
        (PathBuf::from("."), String::new())
    };
    let mut frontier = vec![start];

    for component in &components {
        let mut next = Vec::new();
        for (dir, prefix) in &frontier {
            if pattern_has_active_wildcard(component) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                let mut names: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|name| {
                        // Leading-dot files need an explicit leading dot.
                        if name.starts_with('.') && !component.starts_with('.') {
                            return false;
                        }
                        glob_match(component, name)
                    })
                    .collect();
                names.sort();
                for name in names {
                    next.push((dir.join(&name), format!("{prefix}{name}/")));
                }
            } else {
                // Literal component: descend if it exists on disk.
                let literal = unescape_pattern(component);
                let candidate = dir.join(&literal);
                if candidate.exists() {
                    next.push((candidate, format!("{prefix}{literal}/")));
                }
            }
        }
        frontier = next;
    }

    // Strip the trailing `/` each display prefix accumulated.
    let mut out: Vec<String> = frontier
        .into_iter()
        .map(|(_, prefix)| prefix.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out
}

/// Render a shell [`ast::Word`] as a `case` pattern: like [`literal_word`],
/// but unquoted `*`/`?` are kept as glob wildcards instead of being
/// rejected outright — that's exactly what makes them meaningful in a
/// `case` pattern (`Linux*)`, `x86_64|amd64)`, a bare `*)` default, ...).
/// A `*`/`?`/`\` that came from a quoted or escaped part of the word —
/// or from an expansion's value — is escaped with a leading `\` in the
/// result so policy.rs's matcher treats it as the literal character bash
/// would, not a wildcard.
pub fn case_pattern_word(word: &ast::Word, ctx: &mut ExpandCtx) -> Result<String, String> {
    render_pattern_text(&word.value, ctx)
}

/// [`case_pattern_word`] over raw pattern source text (a
/// `${VAR#pattern}`'s pattern, which brush keeps unparsed).
fn render_pattern_text(text: &str, ctx: &mut ExpandCtx) -> Result<String, String> {
    let pieces = parse_word_pieces(text)?;
    let mut out = String::new();
    for piece in &pieces {
        push_pattern_piece(&piece.piece, &mut out, true, ctx)?;
    }
    Ok(out)
}

fn push_pattern_piece(
    piece: &WordPiece,
    out: &mut String,
    unquoted: bool,
    ctx: &mut ExpandCtx,
) -> Result<(), String> {
    match piece {
        WordPiece::Text(s) => {
            if unquoted {
                // Glob metacharacters keep their special meaning here.
                out.push_str(s);
            } else {
                for c in s.chars() {
                    push_literal_pattern_char(c, out);
                }
            }
            Ok(())
        }
        WordPiece::SingleQuotedText(s) => {
            for c in s.chars() {
                push_literal_pattern_char(c, out);
            }
            Ok(())
        }
        WordPiece::EscapeSequence(s) => {
            // Always a backslash followed by exactly the escaped character.
            push_literal_pattern_char(s[1..].chars().next().unwrap(), out);
            Ok(())
        }
        WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
            for p in inner {
                push_pattern_piece(&p.piece, out, false, ctx)?;
            }
            Ok(())
        }
        WordPiece::AnsiCQuotedText(_) => Err("ANSI-C quoting ($'...') is not supported yet".into()),
        WordPiece::TildeExpansion(brush_parser::word::TildeExpr::Home) => {
            match std::env::var("HOME") {
                Ok(home) => {
                    out.push_str(&home);
                    Ok(())
                }
                Err(_) => Err("cannot expand `~`: $HOME is not set".into()),
            }
        }
        WordPiece::TildeExpansion(_) => {
            Err("tilde expansion is only supported for `~` (the home directory)".into())
        }
        WordPiece::ParameterExpansion(expr) => {
            // An expansion's *value* is matched literally, exactly as
            // bash treats an unquoted variable in a case pattern whose
            // value contains glob characters... it doesn't, but quoted
            // semantics are the safe direction: never let runtime data
            // smuggle in a wildcard.
            for c in resolve_parameter_expansion(expr, ctx)?.chars() {
                push_literal_pattern_char(c, out);
            }
            Ok(())
        }
        WordPiece::CommandSubstitution(cmd) | WordPiece::BackquotedCommandSubstitution(cmd) => {
            for c in run_substitution(cmd, ctx)?.chars() {
                push_literal_pattern_char(c, out);
            }
            Ok(())
        }
        WordPiece::ArithmeticExpression(_) => {
            Err("arithmetic expansion is not supported yet".into())
        }
    }
}

/// Append `c` to a case pattern's literal (quoted/escaped) text,
/// escaping it first if it's one of the matcher's own metacharacters so
/// it's matched as itself rather than as a wildcard.
fn push_literal_pattern_char(c: char, out: &mut String) {
    if c == '*' || c == '?' || c == '\\' {
        out.push('\\');
    }
    out.push(c);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refuse() -> RefuseSubstituter {
        RefuseSubstituter("command substitution refused in this test")
    }

    fn first_suffix_word(script: &str) -> ast::Word {
        let program = parse(script).expect("should parse");
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        w.clone()
    }

    fn simple_words(script: &str) -> Vec<String> {
        let program = parse(script).expect("should parse");
        let item = &program.complete_commands[0].0[0];
        let ast::Command::Simple(cmd) = &item.0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let mut session = Session::new();
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session: &mut session,
            subst: &mut subst,
        };
        let mut words = vec![literal_word(cmd.word_or_name.as_ref().unwrap(), &mut ctx).unwrap()];
        if let Some(suffix) = &cmd.suffix {
            for item in &suffix.0 {
                let ast::CommandPrefixOrSuffixItem::Word(w) = item else {
                    panic!("expected a plain word suffix item");
                };
                words.push(literal_word(w, &mut ctx).unwrap());
            }
        }
        words
    }

    #[test]
    fn parses_plain_words() {
        assert_eq!(
            simple_words("mkdir -p /opt/tool"),
            vec!["mkdir", "-p", "/opt/tool"]
        );
    }

    #[test]
    fn honors_quotes() {
        assert_eq!(
            simple_words(r#"echo 'hello world' "and more""#),
            vec!["echo", "hello world", "and more"]
        );
    }

    #[test]
    fn joins_continuation_lines() {
        assert_eq!(
            simple_words("echo one \\\n  two"),
            vec!["echo", "one", "two"]
        );
    }

    #[test]
    fn parses_full_grammar() {
        // Constructs the old hand-rolled parser rejected outright now
        // parse fine; the evaluator decides what to do with them.
        assert!(parse("if true; then echo hi; fi").is_ok());
        assert!(parse("for f in a b c; do echo \"$f\"; done").is_ok());
        assert!(parse("curl example.com | sh").is_ok());
    }

    #[test]
    fn rejects_unterminated_quotes() {
        assert!(parse("echo 'unterminated").is_err());
    }

    #[test]
    fn tilde_expands_to_home() {
        let home = std::env::var("HOME").expect("test environment should have $HOME set");
        assert_eq!(
            simple_words("echo ~/.bashrc"),
            vec!["echo".to_string(), format!("{home}/.bashrc")]
        );
    }

    fn render_in(script: &str, session: &mut Session) -> Result<String, String> {
        let word = first_suffix_word(script);
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session,
            subst: &mut subst,
        };
        literal_word(&word, &mut ctx)
    }

    fn render(script: &str) -> Result<String, String> {
        render_in(script, &mut Session::new())
    }

    fn fields_in(script: &str, session: &mut Session) -> Result<Vec<String>, String> {
        let word = first_suffix_word(script);
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session,
            subst: &mut subst,
        };
        word_fields(&word, &mut ctx)
    }

    #[test]
    fn tilde_user_expansion_is_not_supported() {
        assert!(render("echo ~someuser/x").is_err());
    }

    #[test]
    fn unset_variable_expands_empty_by_default_and_is_rejected_under_nounset() {
        // bash's default: unset expands to empty.
        assert_eq!(render("echo $HOME_BUT_NOT_REALLY_XYZZY").unwrap(), "");
        // After the script's own `set -u`, it's refused instead.
        let mut session = Session::new();
        session.set_nounset(true);
        assert!(render_in("echo $HOME_BUT_NOT_REALLY_XYZZY", &mut session).is_err());
    }

    #[test]
    fn literal_word_expands_a_tracked_variable() {
        let mut session = Session::new();
        session.set_variable("FOO", "bar");
        assert_eq!(render_in("echo $FOO", &mut session).unwrap(), "bar");
    }

    #[test]
    fn literal_word_expands_a_real_environment_variable_as_a_fallback() {
        let home = std::env::var("HOME").expect("test environment should have $HOME set");
        assert_eq!(render("echo ${HOME}").unwrap(), home);
    }

    #[test]
    fn literal_word_allows_a_lone_bracket() {
        // The `[` test command (and any filename that just happens to
        // contain a `[`) isn't rejected as "globbing": a lone `[` has no
        // matching `]`, so it's not an actual bracket expression.
        let program = parse("[ -f x ]").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let mut session = Session::new();
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session: &mut session,
            subst: &mut subst,
        };
        assert_eq!(
            literal_word(cmd.word_or_name.as_ref().unwrap(), &mut ctx).unwrap(),
            "["
        );
    }

    #[test]
    fn literal_word_still_rejects_a_real_bracket_expression() {
        assert!(render("echo [ab]").is_err());
    }

    #[test]
    fn identity_variables_answer_as_bash() {
        assert!(render("echo ${BASH_VERSION}").unwrap().contains("iish"));
        assert_eq!(render("echo \"${ZSH_VERSION}\"").unwrap(), "");
    }

    #[test]
    fn session_variables_shadow_identity_and_environment() {
        let mut session = Session::new();
        session.set_variable("BASH_VERSION", "overridden");
        assert_eq!(
            render_in("echo ${BASH_VERSION}", &mut session).unwrap(),
            "overridden"
        );
    }

    #[test]
    fn special_parameters_resolve() {
        let mut session = Session::new();
        session.set_last_status(3);
        session.push_frame("f", vec!["one".into(), "two words".into()]);
        assert_eq!(render_in("echo $?", &mut session).unwrap(), "3");
        assert_eq!(render_in("echo $#", &mut session).unwrap(), "2");
        assert_eq!(render_in("echo $1", &mut session).unwrap(), "one");
        assert_eq!(render_in("echo \"$2\"", &mut session).unwrap(), "two words");
        assert_eq!(render_in("echo $0", &mut session).unwrap(), "iish");
        assert_eq!(
            render_in("echo \"$@\"", &mut session).unwrap(),
            "one two words"
        );
    }

    #[test]
    fn unset_positional_parameter_is_rejected_under_nounset() {
        let mut session = Session::new();
        session.set_nounset(true);
        session.push_frame("f", vec!["only".into()]);
        assert!(render_in("echo $2", &mut session).is_err());
        session.set_nounset(false);
        assert_eq!(render_in("echo \"$2\"", &mut session).unwrap(), "");
    }

    #[test]
    fn at_expansion_preserves_argument_boundaries_in_fields() {
        let mut session = Session::new();
        session.push_frame("f", vec!["one".into(), "two words".into()]);
        assert_eq!(
            fields_in("main \"$@\"", &mut session).unwrap(),
            vec!["one", "two words"]
        );
        // "$*" joins into a single field instead.
        assert_eq!(
            fields_in("main \"$*\"", &mut session).unwrap(),
            vec!["one two words"]
        );
    }

    #[test]
    fn empty_at_expansion_produces_zero_fields() {
        let mut session = Session::new();
        assert!(fields_in("main \"$@\"", &mut session).unwrap().is_empty());
    }

    #[test]
    fn lone_unquoted_variable_field_splits() {
        let mut session = Session::new();
        session.set_variable("FLAGS", "  -a   -b ");
        assert_eq!(
            fields_in("cmd $FLAGS", &mut session).unwrap(),
            vec!["-a", "-b"]
        );
        session.set_variable("FLAGS", "");
        assert!(fields_in("cmd $FLAGS", &mut session).unwrap().is_empty());
    }

    #[test]
    fn quoted_variable_never_field_splits() {
        let mut session = Session::new();
        session.set_variable("NAME", "two words");
        assert_eq!(
            fields_in("cmd \"$NAME\"", &mut session).unwrap(),
            vec!["two words"]
        );
    }

    #[test]
    fn unquoted_wildcard_expands_against_the_filesystem() {
        let dir = std::env::temp_dir().join(format!("iish-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("man/man1")).unwrap();
        std::fs::write(dir.join("man/man1/zoxide.1"), b"x").unwrap();
        std::fs::write(dir.join("man/man1/zoxide-add.1"), b"x").unwrap();
        std::fs::write(dir.join("other.txt"), b"x").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let mut session = Session::new();
        // A quoted prefix plus an unquoted `*`, exactly zoxide's
        // `cp -- "man/man1/"*` shape: expands to the two manpages, sorted.
        let got = fields_in("cp \"man/man1/\"*", &mut session).unwrap();
        assert_eq!(got, vec!["man/man1/zoxide-add.1", "man/man1/zoxide.1"]);

        // A wildcard that matches nothing keeps the literal pattern.
        let got = fields_in("cp nomatch-*.zzz", &mut session).unwrap();
        assert_eq!(got, vec!["nomatch-*.zzz"]);

        std::env::set_current_dir(&prev).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn quoted_wildcard_stays_literal() {
        // A `*` inside quotes is not a wildcard: it must not glob, even
        // if it would match something on disk.
        let mut session = Session::new();
        assert_eq!(fields_in("echo \"*\"", &mut session).unwrap(), vec!["*"]);
    }

    #[test]
    fn an_expansions_value_never_globs() {
        // A `*` that arrives via a variable's value is data, not a
        // wildcard: it stays literal (no filesystem expansion), so
        // runtime data can't smuggle in a glob.
        let mut session = Session::new();
        session.set_variable("STAR", "*");
        assert_eq!(fields_in("echo $STAR", &mut session).unwrap(), vec!["*"]);
    }

    #[test]
    fn default_value_operators() {
        let mut session = Session::new();
        assert_eq!(
            render_in("echo \"${UNSET_XYZ:-fallback}\"", &mut session).unwrap(),
            "fallback"
        );
        assert_eq!(
            render_in("echo \"${UNSET_XYZ-}\"", &mut session).unwrap(),
            ""
        );
        session.set_variable("EMPTY", "");
        // `:-` treats empty as missing; `-` does not.
        assert_eq!(
            render_in("echo \"${EMPTY:-fb}\"", &mut session).unwrap(),
            "fb"
        );
        assert_eq!(render_in("echo \"${EMPTY-fb}\"", &mut session).unwrap(), "");
        session.set_variable("SET", "value");
        assert_eq!(
            render_in("echo \"${SET:-fb}\"", &mut session).unwrap(),
            "value"
        );
        assert_eq!(
            render_in("echo \"${SET:+alt}\"", &mut session).unwrap(),
            "alt"
        );
        assert_eq!(
            render_in("echo \"${EMPTY:+alt}\"", &mut session).unwrap(),
            ""
        );
    }

    #[test]
    fn default_value_may_itself_expand() {
        let mut session = Session::new();
        session.set_variable("FALLBACK", "resolved");
        assert_eq!(
            render_in("echo \"${UNSET_XYZ:-${FALLBACK}}\"", &mut session).unwrap(),
            "resolved"
        );
    }

    #[test]
    fn assign_default_operator_assigns() {
        let mut session = Session::new();
        assert_eq!(
            render_in("echo \"${NEWVAR:=assigned}\"", &mut session).unwrap(),
            "assigned"
        );
        assert_eq!(session.get_variable("NEWVAR"), Some("assigned"));
    }

    #[test]
    fn parameter_length() {
        let mut session = Session::new();
        session.set_variable("STR", "four");
        assert_eq!(render_in("echo \"${#STR}\"", &mut session).unwrap(), "4");
    }

    #[test]
    fn command_substitution_calls_the_substituter() {
        struct Fixed;
        impl Substituter for Fixed {
            fn substitute(
                &mut self,
                _session: &mut Session,
                command: &str,
            ) -> Result<String, String> {
                assert_eq!(command.trim(), "uname -s");
                Ok("Linux\n\n".to_string())
            }
        }
        let word = first_suffix_word("echo \"os: $(uname -s)\"");
        let mut session = Session::new();
        let mut subst = Fixed;
        let mut ctx = ExpandCtx {
            session: &mut session,
            subst: &mut subst,
        };
        // Trailing newlines are stripped, interior text preserved.
        assert_eq!(literal_word(&word, &mut ctx).unwrap(), "os: Linux");
    }

    #[test]
    fn refused_substitution_reports_its_reason() {
        let err = render("echo $(whoami)").unwrap_err();
        assert!(err.contains("refused in this test"), "{err}");
    }

    fn case_patterns(script: &str) -> Vec<String> {
        let program = parse(script).expect("should parse");
        let ast::Command::Compound(ast::CompoundCommand::CaseClause(case), _) =
            &program.complete_commands[0].0[0].0.first.seq[0]
        else {
            panic!("expected a case clause");
        };
        let mut session = Session::new();
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session: &mut session,
            subst: &mut subst,
        };
        case.cases[0]
            .patterns
            .iter()
            .map(|p| case_pattern_word(p, &mut ctx).unwrap())
            .collect()
    }

    #[test]
    fn case_pattern_word_keeps_unquoted_glob_meaningful() {
        assert_eq!(case_patterns("case x in Linux*) ;; esac"), vec!["Linux*"]);
    }

    #[test]
    fn case_pattern_word_escapes_quoted_glob_metachars() {
        assert_eq!(
            case_patterns(r#"case x in "*") ;; esac"#),
            vec![r"\*".to_string()]
        );
    }

    #[test]
    fn case_pattern_word_escapes_an_expansions_value() {
        let program = parse("case x in ${PAT}) ;; esac").unwrap();
        let ast::Command::Compound(ast::CompoundCommand::CaseClause(case), _) =
            &program.complete_commands[0].0[0].0.first.seq[0]
        else {
            panic!("expected a case clause");
        };
        let mut session = Session::new();
        session.set_variable("PAT", "a*b");
        let mut subst = refuse();
        let mut ctx = ExpandCtx {
            session: &mut session,
            subst: &mut subst,
        };
        assert_eq!(
            case_pattern_word(&case.cases[0].patterns[0], &mut ctx).unwrap(),
            r"a\*b"
        );
    }
}
