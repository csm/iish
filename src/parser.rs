//! Bash parsing, delegated to brush-parser (see docs/parser-eval.md).
//!
//! iish does not implement bash grammar itself. This module hands the
//! script to brush-parser and returns its AST, or a top-level syntax
//! error. Deciding what iish actually understands and is willing to run
//! is the evaluator's job (`policy.rs`): it walks that AST and denies
//! whatever construct it doesn't implement, node by node. That is the
//! same "if we didn't understand it, we don't run it" posture the old
//! hand-rolled parser used to enforce directly, just moved one layer up
//! now that parsing itself covers the full grammar.

use std::collections::HashMap;

pub use brush_parser::ast;
pub use brush_parser::word::WordPiece;
use brush_parser::word::{Parameter, ParameterExpr};

/// Parser options shared across script and word parsing.
fn options() -> brush_parser::ParserOptions {
    brush_parser::ParserOptions::default()
}

/// Parse a whole script into brush-parser's AST.
pub fn parse(script: &str) -> Result<ast::Program, String> {
    let mut parser = brush_parser::Parser::new(script.as_bytes(), &options());
    parser.parse_program().map_err(|e| e.to_string())
}

/// Render a shell [`ast::Word`] to a literal string, if it is one — i.e.
/// contains no command substitution, tilde expansion, ANSI-C quoting, or
/// unquoted globbing, and no parameter expansion beyond a plain
/// `$VAR`/`${VAR}` reference (resolved against `vars` — this run's
/// bare-assignment-tracked shell variables — falling back to the real
/// process environment, same as `~` already falls back to `$HOME`).
/// Those all require expansion machinery iish does not implement yet, so
/// a word that needs any of them is rejected with a reason instead of
/// being guessed at.
pub fn literal_word(word: &ast::Word, vars: &HashMap<String, String>) -> Result<String, String> {
    let pieces = brush_parser::word::parse(&word.value, &options())
        .map_err(|e| format!("could not parse word `{}`: {e}", word.value))?;
    let mut out = String::new();
    for piece in &pieces {
        push_literal_piece(&piece.piece, &mut out, true, vars)?;
    }
    Ok(out)
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

/// Append one word piece's literal text to `out`, or fail with the reason
/// it can't be rendered without expansion. `unquoted` is true for pieces
/// that sit directly in the word (where bash would still glob-expand
/// `*`/`?`/`[`) and false for pieces nested inside double quotes (where
/// those characters are already literal).
fn push_literal_piece(
    piece: &WordPiece,
    out: &mut String,
    unquoted: bool,
    vars: &HashMap<String, String>,
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
                push_literal_piece(&p.piece, out, false, vars)?;
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
            out.push_str(&resolve_parameter_expansion(expr, vars)?);
            Ok(())
        }
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_) => {
            Err("command substitution is not supported yet".into())
        }
        WordPiece::ArithmeticExpression(_) => {
            Err("arithmetic expansion is not supported yet".into())
        }
    }
}

/// Resolve a parameter expansion to its literal text. Only the plain
/// `$VAR`/`${VAR}` form (a direct, non-indirect reference to a named
/// variable) is supported: default/alternative-value operators
/// (`${VAR:-x}`, `${VAR:+x}`, ...), pattern removal (`${VAR#x}`,
/// `${VAR%x}`, ...), length (`${#VAR}`), indirection (`${!VAR}`),
/// positional (`$1`) and special (`$?`, `$@`, `$#`, ...) parameters, and
/// array variables are all real bash features installers do use, just
/// not ones iish implements yet.
fn resolve_parameter_expansion(
    expr: &ParameterExpr,
    vars: &HashMap<String, String>,
) -> Result<String, String> {
    match expr {
        ParameterExpr::Parameter {
            parameter: Parameter::Named(name),
            indirect: false,
        } => resolve_named_variable(name, vars),
        ParameterExpr::Parameter { indirect: true, .. } => {
            Err("indirect parameter expansion (`${!VAR}`) is not supported yet".into())
        }
        ParameterExpr::Parameter {
            parameter: Parameter::Special(_),
            ..
        } => Err("special parameters (`$?`, `$#`, `$@`, `$*`, ...) are not supported yet".into()),
        ParameterExpr::Parameter {
            parameter: Parameter::Positional(_),
            ..
        } => Err("positional parameters (`$1`, `$2`, ...) are not supported yet".into()),
        ParameterExpr::Parameter {
            parameter: Parameter::NamedWithIndex { .. } | Parameter::NamedWithAllIndices { .. },
            ..
        } => Err("array variable expansion is not supported yet".into()),
        _ => Err(
            "this form of parameter expansion (`${VAR:-default}`, `${VAR#pattern}`, \
             `${#VAR}`, ...) is not supported yet"
                .into(),
        ),
    }
}

/// `$VAR`/`${VAR}`: this run's own bare-assignment-tracked value takes
/// priority (matching bash, where assigning a variable always shadows
/// whatever the process environment had), falling back to the real
/// process environment — the same fallback `~` already gets for
/// `$HOME`. An unset name is rejected rather than expanding to an empty
/// string: iish's execution model already behaves as if `nounset` were
/// always on (see policy.rs's `evaluate_set`).
fn resolve_named_variable(name: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    if let Some(value) = vars.get(name) {
        return Ok(value.clone());
    }
    std::env::var(name).map_err(|_| format!("`${name}` is unset"))
}

/// Render a shell [`ast::Word`] as a `case` pattern: like [`literal_word`],
/// expansion of any kind is rejected, but unquoted `*`/`?` are kept as
/// glob wildcards instead of being rejected outright — that's exactly
/// what makes them meaningful in a `case` pattern (`Linux*)`, `x86_64|
/// amd64)`, a bare `*)` default, ...). A `*`/`?`/`\` that came from a
/// quoted or escaped part of the word is escaped with a leading `\` in
/// the result so policy.rs's matcher treats it as the literal character
/// bash would, not a wildcard.
pub fn case_pattern_word(word: &ast::Word) -> Result<String, String> {
    let pieces = brush_parser::word::parse(&word.value, &options())
        .map_err(|e| format!("could not parse word `{}`: {e}", word.value))?;
    let mut out = String::new();
    for piece in &pieces {
        push_pattern_piece(&piece.piece, &mut out, true)?;
    }
    Ok(out)
}

fn push_pattern_piece(piece: &WordPiece, out: &mut String, unquoted: bool) -> Result<(), String> {
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
                push_pattern_piece(&p.piece, out, false)?;
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
        WordPiece::ParameterExpansion(_) => Err("variable expansion is not supported yet".into()),
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_) => {
            Err("command substitution is not supported yet".into())
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

    fn no_vars() -> HashMap<String, String> {
        HashMap::new()
    }

    fn simple_words(script: &str) -> Vec<String> {
        let program = parse(script).expect("should parse");
        let item = &program.complete_commands[0].0[0];
        let ast::Command::Simple(cmd) = &item.0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let vars = no_vars();
        let mut words = vec![literal_word(cmd.word_or_name.as_ref().unwrap(), &vars).unwrap()];
        if let Some(suffix) = &cmd.suffix {
            for item in &suffix.0 {
                let ast::CommandPrefixOrSuffixItem::Word(w) = item else {
                    panic!("expected a plain word suffix item");
                };
                words.push(literal_word(w, &vars).unwrap());
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

    #[test]
    fn tilde_user_expansion_is_not_supported() {
        let program = parse("echo ~someuser/x").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        assert!(literal_word(w, &no_vars()).is_err());
    }

    #[test]
    fn literal_word_rejects_expansion_of_an_unset_variable() {
        let program = parse("echo $HOME_BUT_NOT_REALLY_XYZZY").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        assert!(literal_word(w, &no_vars()).is_err());
    }

    #[test]
    fn literal_word_expands_a_tracked_variable() {
        let program = parse("echo $FOO").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        let mut vars = no_vars();
        vars.insert("FOO".to_string(), "bar".to_string());
        assert_eq!(literal_word(w, &vars).unwrap(), "bar");
    }

    #[test]
    fn literal_word_expands_a_real_environment_variable_as_a_fallback() {
        let program = parse("echo ${HOME}").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        let home = std::env::var("HOME").expect("test environment should have $HOME set");
        assert_eq!(literal_word(w, &no_vars()).unwrap(), home);
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
        assert_eq!(
            literal_word(cmd.word_or_name.as_ref().unwrap(), &no_vars()).unwrap(),
            "["
        );
    }

    #[test]
    fn literal_word_still_rejects_a_real_bracket_expression() {
        let program = parse("echo [ab]").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        assert!(literal_word(w, &no_vars()).is_err());
    }

    fn case_patterns(script: &str) -> Vec<String> {
        let program = parse(script).expect("should parse");
        let ast::Command::Compound(ast::CompoundCommand::CaseClause(case), _) =
            &program.complete_commands[0].0[0].0.first.seq[0]
        else {
            panic!("expected a case clause");
        };
        case.cases[0]
            .patterns
            .iter()
            .map(|p| case_pattern_word(p).unwrap())
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
}
