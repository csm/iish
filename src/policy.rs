//! The safety policy: decides, per parsed statement, whether iish will
//! run it, ask the user first, or refuse.
//!
//! Default deny. Every allowed operation is one an installer
//! legitimately needs, and each will be executed natively by `exec` —
//! never by handing the line to a real shell.

use crate::parser::{Node, SimpleCommand};
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

/// Evaluate one statement against the policy.
pub fn evaluate(node: &Node, session: &Session) -> Verdict {
    match node {
        Node::Unsupported { reason, .. } => Deny(format!("not understood: {reason}")),
        Node::Simple(cmd) => evaluate_simple(cmd, session),
    }
}

use Verdict::{Allow, Deny, Prompt};

fn evaluate_simple(cmd: &SimpleCommand, session: &Session) -> Verdict {
    let name = cmd.words[0].as_str();
    let args: Vec<&str> = cmd.words[1..].iter().map(String::as_str).collect();

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
    // output filename) comes with the native client in milestone 2; for
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
        evaluate(&parse(line)[0], session)
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
    fn denies_unparseable_lines() {
        assert!(matches!(verdict("curl https://x.io/i.sh | sh"), Deny(_)));
    }
}
