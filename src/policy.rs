//! The safety policy: decides, per parsed statement, whether iish will
//! run it, ask the user first, or refuse.
//!
//! Default deny. The evaluator walks brush-parser's real bash AST
//! (`parser::ast`) and only allows the specific shapes it recognizes as
//! safe installer operations; every construct it does not yet implement
//! — pipelines, control flow, functions, redirection, expansions, and
//! so on — is denied here. This is the "if we didn't understand it, we
//! don't run it" posture the old hand-rolled parser used to enforce by
//! refusing to tokenize; now that parsing covers the full grammar, the
//! evaluator enforces it instead.

use crate::parser::{ast, literal_word};
use crate::state::Session;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Safe to execute.
    Allow(String),
    /// Possibly fine, but the user must confirm (e.g. overwriting a
    /// pre-existing file).
    Prompt(String),
    /// Refused.
    Deny(String),
}

use Verdict::{Allow, Deny, Prompt};

/// One top-level statement in the script, together with its verdict.
pub struct Statement {
    /// The statement reconstructed from the AST, for display.
    pub raw: String,
    pub verdict: Verdict,
}

/// Evaluate every top-level statement of a parsed program against the
/// policy, in source order.
pub fn evaluate_program(program: &ast::Program, session: &Session) -> Vec<Statement> {
    program
        .complete_commands
        .iter()
        .flat_map(|list| list.0.iter())
        .map(|item| Statement {
            raw: item.0.to_string(),
            verdict: evaluate_list_item(item, session),
        })
        .collect()
}

fn evaluate_list_item(item: &ast::CompoundListItem, session: &Session) -> Verdict {
    let ast::CompoundListItem(and_or, separator) = item;
    if matches!(separator, ast::SeparatorOperator::Async) {
        return Deny("background jobs (`&`) are not implemented yet".into());
    }
    evaluate_and_or_list(and_or, session)
}

fn evaluate_and_or_list(list: &ast::AndOrList, session: &Session) -> Verdict {
    if !list.additional.is_empty() {
        return Deny("command lists joined by `&&`/`||` are not implemented yet".into());
    }
    evaluate_pipeline(&list.first, session)
}

fn evaluate_pipeline(pipeline: &ast::Pipeline, session: &Session) -> Verdict {
    if pipeline.timed.is_some() {
        return Deny("`time` is not implemented yet".into());
    }
    if pipeline.bang {
        return Deny("`!` pipeline negation is not implemented yet".into());
    }
    match pipeline.seq.as_slice() {
        [] => Deny("empty pipeline".into()),
        [only] => evaluate_command(only, session),
        stages => {
            if stages.iter().any(is_shell_invocation) {
                Deny(
                    "piping into a shell is exactly what iish exists to replace; refusing"
                        .into(),
                )
            } else {
                Deny("pipelines are not implemented yet".into())
            }
        }
    }
}

/// True if `cmd` is a bare invocation of a shell — the `| sh` half of
/// the `curl | sh` anti-pattern iish exists to intercept.
fn is_shell_invocation(cmd: &ast::Command) -> bool {
    let ast::Command::Simple(sc) = cmd else {
        return false;
    };
    sc.word_or_name
        .as_ref()
        .map(|w| matches!(w.value.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh"))
        .unwrap_or(false)
}

fn evaluate_command(cmd: &ast::Command, session: &Session) -> Verdict {
    match cmd {
        ast::Command::Simple(sc) => evaluate_simple_command(sc, session),
        ast::Command::Function(_) => Deny("function definitions are not implemented yet".into()),
        ast::Command::ExtendedTest(_, redirects) => {
            if redirects.is_some() {
                return Deny("redirection is not implemented yet".into());
            }
            Deny("`[[ ]]` extended test is not implemented yet".into())
        }
        ast::Command::Compound(compound, redirects) => {
            if redirects.is_some() {
                return Deny("redirection is not implemented yet".into());
            }
            Deny(format!("{} are not implemented yet", compound_kind(compound)))
        }
    }
}

fn compound_kind(compound: &ast::CompoundCommand) -> &'static str {
    match compound {
        ast::CompoundCommand::Arithmetic(_) => "arithmetic commands",
        ast::CompoundCommand::ArithmeticForClause(_) => "arithmetic for-loops",
        ast::CompoundCommand::BraceGroup(_) => "brace groups",
        ast::CompoundCommand::Subshell(_) => "subshells",
        ast::CompoundCommand::ForClause(_) => "for-loops",
        ast::CompoundCommand::CaseClause(_) => "case statements",
        ast::CompoundCommand::IfClause(_) => "if statements",
        ast::CompoundCommand::WhileClause(_) => "while-loops",
        ast::CompoundCommand::UntilClause(_) => "until-loops",
        ast::CompoundCommand::Coprocess(_) => "coprocesses",
    }
}

fn evaluate_simple_command(cmd: &ast::SimpleCommand, session: &Session) -> Verdict {
    if let Some(prefix) = &cmd.prefix {
        if !prefix.0.is_empty() {
            return Deny(if cmd.word_or_name.is_none() {
                "bare variable assignment (`VAR=value`) is not implemented yet".into()
            } else {
                "`VAR=value` prefix assignments are not implemented yet".into()
            });
        }
    }

    let Some(name_word) = &cmd.word_or_name else {
        return Deny("bare variable assignment is not implemented yet".into());
    };
    let name = match literal_word(name_word) {
        Ok(n) => n,
        Err(reason) => return Deny(reason),
    };

    let mut args: Vec<String> = Vec::new();
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => match literal_word(w) {
                    Ok(s) => args.push(s),
                    Err(reason) => return Deny(reason),
                },
                ast::CommandPrefixOrSuffixItem::AssignmentWord(..) => {
                    return Deny("assignment arguments are not implemented yet".into());
                }
                ast::CommandPrefixOrSuffixItem::IoRedirect(_) => {
                    return Deny("redirection is not implemented yet".into());
                }
                ast::CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return Deny("process substitution is not implemented yet".into());
                }
            }
        }
    }

    evaluate_argv(&name, &args, session)
}

fn evaluate_argv(name: &str, args: &[String], session: &Session) -> Verdict {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    match name {
        // Pure output — harmless.
        "echo" | "printf" | "true" | ":" => Allow("prints output only".into()),

        "mkdir" => evaluate_mkdir(&args),
        "rm" => evaluate_rm(&args, session),
        "curl" | "wget" => evaluate_fetch(name, &args),

        // Recognized installer staples we haven't implemented yet.
        // Listed separately from the generic deny so the report shows
        // them as "planned" rather than "unknown".
        "cp" | "mv" | "tar" | "chmod" | "install" | "ln" | "cd" | "export" | "source"
        | "." => Deny(format!("`{name}` is recognized but not implemented yet")),

        other => Deny(format!("`{other}` is not on the installer allowlist")),
    }
}

fn evaluate_mkdir(args: &[&str]) -> Verdict {
    let paths: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        return Deny("mkdir with no path".into());
    }
    if let Some(existing) = paths.iter().find(|p| Path::new(**p).exists()) {
        return Prompt(format!("directory `{existing}` already exists"));
    }
    Allow("creates new directories only".into())
}

fn evaluate_rm(args: &[&str], session: &Session) -> Verdict {
    let paths: Vec<&&str> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        return Deny("rm with no path".into());
    }
    for path in &paths {
        if !session.owns(Path::new(**path)) {
            return Deny(format!(
                "`{path}` was not created by this script; refusing to delete"
            ));
        }
    }
    Allow("deletes only paths this script created".into())
}

/// curl/wget: only plain GET-to-file shapes will be permitted, and iish
/// will perform the fetch itself with its own HTTP client rather than
/// invoking the real binary. For now we only vet the obvious flags.
fn evaluate_fetch(name: &str, args: &[&str]) -> Verdict {
    const FORBIDDEN: &[(&str, &str)] = &[
        ("-X", "non-GET method"),
        ("--request", "non-GET method"),
        ("-d", "sends data"),
        ("--data", "sends data"),
        ("-F", "sends data"),
        ("--form", "sends data"),
        ("-T", "uploads"),
        ("--upload-file", "uploads"),
        ("--post-data", "sends data"),
        ("--method", "non-GET method"),
    ];
    for arg in args {
        if let Some((flag, why)) = FORBIDDEN
            .iter()
            .find(|(f, _)| arg == f || arg.starts_with(&format!("{f}=")))
        {
            return Deny(format!("{name} {flag}: {why}; only GET is allowed"));
        }
    }
    // Full flag-table parsing (which non-flag word is the URL vs. an
    // output filename) comes with the native client in milestone 4; for
    // now require an explicit http(s) URL somewhere in the arguments.
    if !args
        .iter()
        .any(|a| a.starts_with("https://") || a.starts_with("http://"))
    {
        return Deny(format!("{name} without an http(s) URL"));
    }
    Allow("GET request, fetched by iish's own HTTP client".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    fn verdict(line: &str) -> Verdict {
        verdict_with(line, &Session::new())
    }

    fn verdict_with(line: &str, session: &Session) -> Verdict {
        let program = parse(line).expect("should parse");
        evaluate_program(&program, session)
            .into_iter()
            .next()
            .expect("should have one statement")
            .verdict
    }

    #[test]
    fn allows_echo() {
        assert!(matches!(verdict("echo hello"), Allow(_)));
    }

    #[test]
    fn denies_unknown_binaries() {
        assert!(matches!(verdict("sudo make install"), Deny(_)));
    }

    #[test]
    fn denies_rm_of_foreign_paths() {
        assert!(matches!(verdict("rm -rf /etc/passwd"), Deny(_)));
    }

    #[test]
    fn allows_rm_of_owned_paths() {
        let mut session = Session::new();
        session.record_created("/tmp/tool-staging");
        assert!(matches!(
            verdict_with("rm -rf /tmp/tool-staging", &session),
            Allow(_)
        ));
    }

    #[test]
    fn denies_curl_post() {
        assert!(matches!(
            verdict("curl -X POST https://example.com"),
            Deny(_)
        ));
    }

    #[test]
    fn allows_curl_get() {
        assert!(matches!(
            verdict("curl -fsSLo installer.tar.gz https://example.com/t.tar.gz"),
            Allow(_)
        ));
    }

    #[test]
    fn denies_piping_to_shell() {
        assert!(matches!(verdict("curl https://x.io/i.sh | sh"), Deny(_)));
    }

    #[test]
    fn denies_pipelines_generally() {
        assert!(matches!(verdict("cat foo | grep bar"), Deny(_)));
    }

    #[test]
    fn denies_expansion() {
        assert!(matches!(verdict("echo $HOME"), Deny(_)));
    }

    #[test]
    fn denies_control_flow_with_specific_reason() {
        match verdict("if true; then echo hi; fi") {
            Deny(reason) => assert!(reason.contains("if statements")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn denies_command_lists() {
        assert!(matches!(verdict("mkdir /tmp/a && mkdir /tmp/b"), Deny(_)));
    }

    #[test]
    fn denies_background_jobs() {
        assert!(matches!(verdict("echo hi &"), Deny(_)));
    }
}
