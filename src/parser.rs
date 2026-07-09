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

pub use brush_parser::ast;
pub use brush_parser::word::WordPiece;

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
/// contains no parameter/command substitution, tilde expansion, ANSI-C
/// quoting, or unquoted globbing. Those all require expansion machinery
/// iish does not implement yet, so a word that needs any of them is
/// rejected with a reason instead of being guessed at.
pub fn literal_word(word: &ast::Word) -> Result<String, String> {
    let pieces = brush_parser::word::parse(&word.value, &options())
        .map_err(|e| format!("could not parse word `{}`: {e}", word.value))?;
    let mut out = String::new();
    for piece in &pieces {
        push_literal_piece(&piece.piece, &mut out, true)?;
    }
    Ok(out)
}

/// Append one word piece's literal text to `out`, or fail with the reason
/// it can't be rendered without expansion. `unquoted` is true for pieces
/// that sit directly in the word (where bash would still glob-expand
/// `*`/`?`/`[`) and false for pieces nested inside double quotes (where
/// those characters are already literal).
fn push_literal_piece(piece: &WordPiece, out: &mut String, unquoted: bool) -> Result<(), String> {
    match piece {
        WordPiece::Text(s) => {
            if unquoted && s.contains(['*', '?', '[']) {
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
                push_literal_piece(&p.piece, out, false)?;
            }
            Ok(())
        }
        WordPiece::AnsiCQuotedText(_) => {
            Err("ANSI-C quoting ($'...') is not supported yet".into())
        }
        WordPiece::TildeExpansion(_) => Err("tilde expansion is not supported yet".into()),
        WordPiece::ParameterExpansion(_) => {
            Err("variable expansion is not supported yet".into())
        }
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_) => {
            Err("command substitution is not supported yet".into())
        }
        WordPiece::ArithmeticExpression(_) => {
            Err("arithmetic expansion is not supported yet".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_words(script: &str) -> Vec<String> {
        let program = parse(script).expect("should parse");
        let item = &program.complete_commands[0].0[0];
        let ast::Command::Simple(cmd) = &item.0.first.seq[0] else {
            panic!("expected a simple command");
        };
        let mut words = vec![literal_word(cmd.word_or_name.as_ref().unwrap()).unwrap()];
        if let Some(suffix) = &cmd.suffix {
            for item in &suffix.0 {
                let ast::CommandPrefixOrSuffixItem::Word(w) = item else {
                    panic!("expected a plain word suffix item");
                };
                words.push(literal_word(w).unwrap());
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
    fn literal_word_rejects_expansion() {
        let program = parse("echo $HOME").unwrap();
        let ast::Command::Simple(cmd) = &program.complete_commands[0].0[0].0.first.seq[0] else {
            panic!("expected simple command");
        };
        let word = &cmd.suffix.as_ref().unwrap().0[0];
        let ast::CommandPrefixOrSuffixItem::Word(w) = word else {
            panic!("expected word");
        };
        assert!(literal_word(w).is_err());
    }
}
