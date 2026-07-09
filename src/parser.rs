//! Minimal bash parser.
//!
//! This is deliberately not a full bash grammar. It handles the subset a
//! well-behaved installer script needs (simple commands, quoting, line
//! continuations, comments) and turns everything else into an explicit
//! [`Node::Unsupported`], which the policy layer denies. The safety
//! posture is: if we didn't understand it, we don't run it.
//!
//! Likely to be replaced by a real bash-grammar crate (yash-syntax or
//! brush-parser) once the project direction settles.

/// One statement of the input script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A plain `argv`-style command: words after quote removal.
    Simple(SimpleCommand),
    /// Something we recognized as bash but do not support (yet).
    Unsupported { raw: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// Words after tokenization and quote removal. Never empty.
    pub words: Vec<String>,
    /// The original source line, for display.
    pub raw: String,
}

/// Shell metacharacters that signal constructs the minimal parser does
/// not understand: pipelines, lists, redirection, substitution, control
/// flow, background jobs.
const UNSUPPORTED_META: &[(char, &str)] = &[
    ('|', "pipelines are not supported yet"),
    (';', "command lists are not supported yet"),
    ('&', "background jobs / && lists are not supported yet"),
    ('<', "redirection is not supported yet"),
    ('>', "redirection is not supported yet"),
    ('`', "command substitution is not supported yet"),
    ('$', "variable/command expansion is not supported yet"),
    ('(', "subshells/functions are not supported yet"),
    (')', "subshells/functions are not supported yet"),
    ('{', "brace groups/expansion are not supported yet"),
    ('}', "brace groups/expansion are not supported yet"),
    ('*', "globbing is not supported yet"),
    ('?', "globbing is not supported yet"),
    ('~', "tilde expansion is not supported yet"),
];

/// Parse a whole script into a sequence of nodes.
pub fn parse(script: &str) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut pending = String::new();

    for line in script.lines() {
        // Backslash line continuation.
        if let Some(stripped) = line.strip_suffix('\\') {
            pending.push_str(stripped);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let logical = std::mem::take(&mut pending);
        if let Some(node) = parse_line(&logical) {
            nodes.push(node);
        }
    }
    if !pending.trim().is_empty() {
        nodes.push(Node::Unsupported {
            raw: pending.trim().to_string(),
            reason: "trailing line continuation at end of input".into(),
        });
    }
    nodes
}

/// Parse one logical line. Returns `None` for blank lines and comments.
fn parse_line(line: &str) -> Option<Node> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    if trimmed.starts_with("#!") {
        return None; // shebang
    }

    match tokenize(trimmed) {
        Ok(words) if words.is_empty() => None,
        Ok(words) => Some(Node::Simple(SimpleCommand {
            words,
            raw: trimmed.to_string(),
        })),
        Err(reason) => Some(Node::Unsupported {
            raw: trimmed.to_string(),
            reason,
        }),
    }
}

/// Split a line into words, honoring single and double quotes.
/// Rejects (as `Err`) any metacharacter we do not support.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => current.push(ch),
                        None => return Err("unterminated single quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('$') | Some('`') => {
                            return Err(
                                "expansion inside double quotes is not supported yet".into()
                            )
                        }
                        Some('\\') => match chars.next() {
                            Some(esc) => current.push(esc),
                            None => return Err("unterminated escape in double quote".into()),
                        },
                        Some(ch) => current.push(ch),
                        None => return Err("unterminated double quote".into()),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(esc) => {
                    in_word = true;
                    current.push(esc);
                }
                None => return Err("trailing backslash".into()),
            },
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            '#' if !in_word => break, // comment to end of line
            c => {
                if let Some((_, reason)) = UNSUPPORTED_META.iter().find(|(m, _)| *m == c) {
                    return Err((*reason).to_string());
                }
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple(script: &str) -> Vec<String> {
        match &parse(script)[0] {
            Node::Simple(cmd) => cmd.words.clone(),
            other => panic!("expected simple command, got {other:?}"),
        }
    }

    #[test]
    fn parses_plain_words() {
        assert_eq!(simple("mkdir -p /opt/tool"), vec!["mkdir", "-p", "/opt/tool"]);
    }

    #[test]
    fn honors_quotes() {
        assert_eq!(
            simple(r#"echo 'hello world' "and more""#),
            vec!["echo", "hello world", "and more"]
        );
    }

    #[test]
    fn skips_comments_and_blanks() {
        assert!(parse("# just a comment\n\n   \n").is_empty());
    }

    #[test]
    fn rejects_pipelines() {
        match &parse("curl example.com | sh")[0] {
            Node::Unsupported { reason, .. } => assert!(reason.contains("pipelines")),
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn rejects_expansion() {
        assert!(matches!(
            &parse("echo $HOME")[0],
            Node::Unsupported { .. }
        ));
    }

    #[test]
    fn joins_continuation_lines() {
        assert_eq!(
            simple("echo one \\\n  two"),
            vec!["echo", "one", "two"]
        );
    }
}
