//! The safety policy: decides, per parsed statement, whether iish will
//! run it, ask the user first, or refuse — and compiles the allowed
//! ones into [`Action`]s for native execution.
//!
//! Default deny. The evaluator walks brush-parser's real bash AST
//! (`parser::ast`) and only allows the specific shapes it recognizes as
//! safe installer operations; every construct it does not yet implement
//! — pipelines, control flow, functions, redirection, expansions, and
//! so on — is denied here. This is the "if we didn't understand it, we
//! don't run it" posture the old hand-rolled parser used to enforce by
//! refusing to tokenize; now that parsing covers the full grammar, the
//! evaluator enforces it instead.

use crate::exec::{Action, FetchOutput, Mode};
use crate::parser::{ast, literal_word};
use crate::state::{self, Session};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Safe to execute; `action` is the compiled operation.
    Allow { reason: String, action: Action },
    /// Possibly fine, but the user must confirm on /dev/tty first
    /// (e.g. overwriting a pre-existing file).
    Prompt { reason: String, action: Action },
    /// Refused.
    Deny { reason: String },
}

fn allow(reason: impl Into<String>, action: Action) -> Verdict {
    Verdict::Allow {
        reason: reason.into(),
        action,
    }
}

fn prompt(reason: impl Into<String>, action: Action) -> Verdict {
    Verdict::Prompt {
        reason: reason.into(),
        action,
    }
}

fn deny(reason: impl Into<String>) -> Verdict {
    Verdict::Deny {
        reason: reason.into(),
    }
}

/// One top-level statement in the script, together with its verdict.
pub struct Statement {
    /// The statement reconstructed from the AST, for display.
    pub raw: String,
    pub verdict: Verdict,
}

/// The top-level statements of a parsed program, in source order. Each
/// must be evaluated against the ledger as it stands when execution
/// reaches it, so callers iterate these and call [`evaluate_item`] one
/// statement at a time.
pub fn items(program: &ast::Program) -> Vec<&ast::CompoundListItem> {
    program
        .complete_commands
        .iter()
        .flat_map(|list| list.0.iter())
        .collect()
}

/// Evaluate one top-level statement against the policy and the current
/// session ledger.
pub fn evaluate_item(item: &ast::CompoundListItem, session: &Session) -> Statement {
    Statement {
        raw: item.0.to_string(),
        verdict: evaluate_list_item(item, session),
    }
}

fn evaluate_list_item(item: &ast::CompoundListItem, session: &Session) -> Verdict {
    let ast::CompoundListItem(and_or, separator) = item;
    if matches!(separator, ast::SeparatorOperator::Async) {
        return deny("background jobs (`&`) are not implemented yet");
    }
    evaluate_and_or_list(and_or, session)
}

fn evaluate_and_or_list(list: &ast::AndOrList, session: &Session) -> Verdict {
    if !list.additional.is_empty() {
        return deny("command lists joined by `&&`/`||` are not implemented yet");
    }
    evaluate_pipeline(&list.first, session)
}

fn evaluate_pipeline(pipeline: &ast::Pipeline, session: &Session) -> Verdict {
    if pipeline.timed.is_some() {
        return deny("`time` is not implemented yet");
    }
    if pipeline.bang {
        return deny("`!` pipeline negation is not implemented yet");
    }
    match pipeline.seq.as_slice() {
        [] => deny("empty pipeline"),
        [only] => evaluate_command(only, session),
        stages => {
            if stages.iter().any(is_shell_invocation) {
                deny("piping into a shell is exactly what iish exists to replace; refusing")
            } else {
                deny("pipelines are not implemented yet")
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
        ast::Command::Function(_) => deny("function definitions are not implemented yet"),
        ast::Command::ExtendedTest(_, redirects) => {
            if redirects.is_some() {
                return deny("redirection is not implemented yet");
            }
            deny("`[[ ]]` extended test is not implemented yet")
        }
        ast::Command::Compound(compound, redirects) => {
            if redirects.is_some() {
                return deny("redirection is not implemented yet");
            }
            deny(format!(
                "{} are not implemented yet",
                compound_kind(compound)
            ))
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
            return deny(if cmd.word_or_name.is_none() {
                "bare variable assignment (`VAR=value`) is not implemented yet"
            } else {
                "`VAR=value` prefix assignments are not implemented yet"
            });
        }
    }

    let Some(name_word) = &cmd.word_or_name else {
        return deny("bare variable assignment is not implemented yet");
    };
    let name = match literal_word(name_word) {
        Ok(n) => n,
        Err(reason) => return deny(reason),
    };

    let mut args: Vec<String> = Vec::new();
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => match literal_word(w) {
                    Ok(s) => args.push(s),
                    Err(reason) => return deny(reason),
                },
                ast::CommandPrefixOrSuffixItem::AssignmentWord(..) => {
                    return deny("assignment arguments are not implemented yet");
                }
                ast::CommandPrefixOrSuffixItem::IoRedirect(_) => {
                    return deny("redirection is not implemented yet");
                }
                ast::CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return deny("process substitution is not implemented yet");
                }
            }
        }
    }

    evaluate_argv(&name, &args, session)
}

fn evaluate_argv(name: &str, args: &[String], session: &Session) -> Verdict {
    match name {
        "true" | ":" => allow("does nothing", Action::Noop),
        "echo" => evaluate_echo(args),
        "printf" => evaluate_printf(args),
        "mkdir" => evaluate_mkdir(args),
        "rm" => evaluate_rm(args, session),
        "chmod" => evaluate_chmod(args, session),
        "curl" => evaluate_curl(args, session),
        "wget" => evaluate_wget(args, session),

        // Recognized installer staples we haven't implemented yet.
        // Listed separately from the generic deny so the report shows
        // them as "planned" rather than "unknown".
        "cp" | "mv" | "tar" | "install" | "ln" | "cd" | "export" | "source" | "." => {
            deny(format!("`{name}` is recognized but not implemented yet"))
        }

        other => deny(format!("`{other}` is not on the installer allowlist")),
    }
}

fn evaluate_echo(args: &[String]) -> Verdict {
    let mut newline = true;
    let mut rest = args;
    // Only leading flags count; after the first non-flag word, `-n` is
    // just text, as in real echo.
    while let Some(first) = rest.first() {
        match first.as_str() {
            "-n" => newline = false,
            "-E" => {} // no escape processing — already our behavior
            "-e" | "-ne" | "-en" => {
                return deny("echo -e escape processing is not implemented yet")
            }
            _ => break,
        }
        rest = &rest[1..];
    }
    let mut text = rest.join(" ");
    if newline {
        text.push('\n');
    }
    allow("prints output only", Action::Print { text })
}

fn evaluate_printf(args: &[String]) -> Verdict {
    let Some((format, rest)) = args.split_first() else {
        return deny("printf with no format string");
    };
    match render_printf(format, rest) {
        Ok(text) => allow("prints output only", Action::Print { text }),
        Err(reason) => deny(reason),
    }
}

/// Render a printf invocation to the text it would output, supporting
/// the subset installers use: `%s`/`%%` directives, `\n`/`\t`/`\r`/`\\`
/// escapes, and format reuse while arguments remain.
fn render_printf(format: &str, args: &[String]) -> Result<String, String> {
    let mut out = String::new();
    let mut remaining = args.iter();
    loop {
        let mut consumed = false;
        let mut chars = format.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        return Err(format!("printf escape `\\{other}` is not implemented yet"))
                    }
                    None => return Err("printf format ends with a lone `\\`".into()),
                },
                '%' => match chars.next() {
                    Some('s') => {
                        // Missing arguments format as empty, as in bash.
                        out.push_str(remaining.next().map(String::as_str).unwrap_or(""));
                        consumed = true;
                    }
                    Some('%') => out.push('%'),
                    Some(other) => {
                        return Err(format!(
                            "printf directive `%{other}` is not implemented yet"
                        ))
                    }
                    None => return Err("printf format ends with a lone `%`".into()),
                },
                other => out.push(other),
            }
        }
        // bash reuses the format until the arguments run out — but only
        // if a pass actually consumes some, else extras are ignored.
        if !consumed || remaining.len() == 0 {
            return Ok(out);
        }
    }
}

fn evaluate_mkdir(args: &[String]) -> Verdict {
    let mut parents = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-p" | "--parents" => parents = true,
            a if a.starts_with('-') => return deny(format!("mkdir option `{a}` is not supported")),
            a => paths.push(state::normalize(Path::new(a))),
        }
    }
    if paths.is_empty() {
        return deny("mkdir with no path");
    }
    if !parents {
        if let Some(existing) = paths.iter().find(|p| p.exists()) {
            return deny(format!(
                "`{}` already exists (mkdir without -p would fail)",
                existing.display()
            ));
        }
    }
    let to_create: Vec<PathBuf> = paths.into_iter().filter(|p| !p.exists()).collect();
    if to_create.is_empty() {
        return allow(
            "all directories already exist; mkdir -p is a no-op",
            Action::Noop,
        );
    }
    allow(
        "creates new directories only",
        Action::MkDir {
            paths: to_create,
            parents,
        },
    )
}

fn evaluate_rm(args: &[String], session: &Session) -> Verdict {
    let mut recursive = false;
    let mut force = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        if let Some(long) = arg.strip_prefix("--") {
            match long {
                "recursive" => recursive = true,
                "force" => force = true,
                _ => return deny(format!("rm option `{arg}` is not supported")),
            }
        } else if let Some(cluster) = arg.strip_prefix('-') {
            if cluster.is_empty() {
                return deny("rm `-` is not supported");
            }
            for c in cluster.chars() {
                match c {
                    'r' | 'R' => recursive = true,
                    'f' => force = true,
                    other => return deny(format!("rm option `-{other}` is not supported")),
                }
            }
        } else {
            paths.push(state::normalize(Path::new(arg)));
        }
    }
    if paths.is_empty() {
        return deny("rm with no path");
    }
    for path in &paths {
        if !session.owns(path) {
            return deny(format!(
                "`{}` was not created by this script; refusing to delete",
                path.display()
            ));
        }
    }
    allow(
        "deletes only paths this script created",
        Action::Remove {
            paths,
            recursive,
            force,
        },
    )
}

fn evaluate_chmod(args: &[String], session: &Session) -> Verdict {
    let Some((mode_str, path_args)) = args.split_first() else {
        return deny("chmod with no mode");
    };
    if mode_str.starts_with('-') {
        return deny(format!("chmod option `{mode_str}` is not supported"));
    }
    let mode = match parse_chmod_mode(mode_str) {
        Ok(mode) => mode,
        Err(reason) => return deny(reason),
    };
    if path_args.is_empty() {
        return deny("chmod with no path");
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in path_args {
        if arg.starts_with('-') {
            return deny(format!("chmod option `{arg}` is not supported"));
        }
        let path = state::normalize(Path::new(arg));
        if !session.owns(&path) {
            return deny(format!(
                "`{}` was not created by this script; chmod is limited to created paths",
                path.display()
            ));
        }
        paths.push(path);
    }
    allow(
        "changes modes only on paths this script created",
        Action::Chmod { mode, paths },
    )
}

fn parse_chmod_mode(s: &str) -> Result<Mode, String> {
    if (1..=4).contains(&s.len()) && s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Ok(Mode::Octal(u32::from_str_radix(s, 8).unwrap()));
    }
    // `[ugoa]*+x` is the only symbolic form installers use in practice.
    if let Some((who, perms)) = s.split_once('+') {
        if perms == "x" && who.chars().all(|c| "ugoa".contains(c)) {
            let mut bits = 0;
            for c in who.chars() {
                bits |= match c {
                    'u' => 0o100,
                    'g' => 0o010,
                    'o' => 0o001,
                    _ => 0o111, // 'a'
                };
            }
            if who.is_empty() {
                bits = 0o111; // bare `+x`, treated as `a+x`
            }
            return Ok(Mode::AddBits(bits));
        }
    }
    Err(format!("chmod mode `{s}` is not supported yet"))
}

/// curl: only plain GET shapes are permitted, and iish performs the
/// fetch itself with its own HTTP client rather than invoking the real
/// binary. Every flag must be on the allowlist below; anything else —
/// non-GET methods, data uploads, `--insecure`, config files, … — is
/// denied by not being on it.
fn evaluate_curl(args: &[String], session: &Session) -> Verdict {
    let mut output: Option<String> = None;
    let mut remote_name = false;
    let mut urls: Vec<&str> = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(long) = arg.strip_prefix("--") {
            let (flag, inline_value) = match long.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (long, None),
            };
            let mut take_value = |what: &str| match inline_value.clone() {
                Some(v) => Ok(v),
                None => iter
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("curl --{flag} is missing its {what}")),
            };
            match flag {
                // Benign behavior flags.
                "fail" | "silent" | "show-error" | "location" | "progress-bar"
                | "no-progress-meter" | "compressed" => {}
                "remote-name" => remote_name = true,
                "output" => match take_value("filename") {
                    Ok(v) => output = Some(v),
                    Err(reason) => return deny(reason),
                },
                // Take a value we don't need: iish's own client decides
                // protocols, retries, and timeouts.
                "proto" | "retry" | "retry-delay" | "connect-timeout" | "max-time" => {
                    if let Err(reason) = take_value("value") {
                        return deny(reason);
                    }
                }
                "insecure" => return deny("curl --insecure disables TLS verification; refusing"),
                _ => return deny(format!("curl option `--{flag}` is not supported by iish")),
            }
        } else if let Some(cluster) = arg.strip_prefix('-') {
            if cluster.is_empty() {
                return deny("curl `-` (stdin) is not supported");
            }
            let mut chars = cluster.chars();
            while let Some(c) = chars.next() {
                match c {
                    'f' | 's' | 'S' | 'L' | '#' => {}
                    'O' => remote_name = true,
                    'o' => {
                        // `-ofile` or `-o file`.
                        let rest: String = chars.collect();
                        let value = if rest.is_empty() {
                            match iter.next() {
                                Some(v) => v.clone(),
                                None => return deny("curl -o is missing its filename"),
                            }
                        } else {
                            rest
                        };
                        output = Some(value);
                        break;
                    }
                    'k' => return deny("curl -k disables TLS verification; refusing"),
                    other => {
                        return deny(format!("curl option `-{other}` is not supported by iish"))
                    }
                }
            }
        } else {
            urls.push(arg);
        }
    }

    finish_fetch("curl", &urls, output, remote_name, session)
}

/// wget, same posture as curl: a small allowlist of flags, GET only,
/// fetched in-process.
fn evaluate_wget(args: &[String], session: &Session) -> Verdict {
    let mut output: Option<String> = None;
    let mut urls: Vec<&str> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-q" | "--quiet" | "-nv" | "--no-verbose" | "--https-only" => {}
            "-O" | "--output-document" => match iter.next() {
                Some(v) => output = Some(v.clone()),
                None => return deny(format!("wget {arg} is missing its filename")),
            },
            a if a.starts_with("--output-document=") => {
                output = Some(a["--output-document=".len()..].to_string());
            }
            "--no-check-certificate" => {
                return deny("wget --no-check-certificate disables TLS verification; refusing")
            }
            a if a.starts_with('-') && a.len() > 1 => {
                return deny(format!("wget option `{a}` is not supported by iish"))
            }
            a => urls.push(a),
        }
    }

    // wget writes to the URL's basename when no -O is given.
    finish_fetch("wget", &urls, output, true, session)
}

/// Shared tail of curl/wget evaluation: validate the URL, resolve where
/// the body goes, and apply the overwrite policy.
fn finish_fetch(
    name: &str,
    urls: &[&str],
    output: Option<String>,
    remote_name: bool,
    session: &Session,
) -> Verdict {
    let url = match urls {
        [] => return deny(format!("{name} without a URL")),
        [url] => (*url).to_string(),
        _ => return deny(format!("{name} with multiple URLs is not supported")),
    };
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return deny(format!(
            "{name}: only http(s) URLs are allowed, got `{url}`"
        ));
    }

    let destination = match output {
        Some(path) if path == "-" => FetchOutput::Stdout,
        Some(path) => FetchOutput::File(state::normalize(Path::new(&path))),
        None if remote_name => {
            // Basename of the URL path, query and fragment stripped.
            let trimmed = url.split(['?', '#']).next().unwrap_or("");
            let after_scheme = trimmed.split_once("://").map(|(_, r)| r).unwrap_or(trimmed);
            let base = match after_scheme.split_once('/') {
                Some((_, path)) => path.rsplit('/').next().unwrap_or(""),
                None => "",
            };
            if base.is_empty() {
                return deny(format!(
                    "{name}: cannot infer an output filename from `{url}`; use -O/-o with a name"
                ));
            }
            FetchOutput::File(state::normalize(Path::new(base)))
        }
        None => FetchOutput::Stdout,
    };

    let action = Action::Fetch {
        url: url.clone(),
        output: destination.clone(),
    };
    match &destination {
        FetchOutput::Stdout => allow(
            format!("GET `{url}` to stdout, fetched by iish's own HTTP client"),
            action,
        ),
        FetchOutput::File(path) if !path.exists() => allow(
            format!(
                "GET `{url}` to new file `{}`, fetched by iish's own HTTP client",
                path.display()
            ),
            action,
        ),
        FetchOutput::File(path) if session.owns(path) => allow(
            format!(
                "GET `{url}` overwrites `{}`, a file this run created",
                path.display()
            ),
            action,
        ),
        FetchOutput::File(path) => prompt(
            format!(
                "GET `{url}` would overwrite pre-existing `{}`",
                path.display()
            ),
            action,
        ),
    }
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
        let item = *items(&program).first().expect("should have one statement");
        evaluate_item(item, session).verdict
    }

    use Verdict::{Allow, Deny, Prompt};

    #[test]
    fn allows_echo() {
        match verdict("echo hello world") {
            Allow {
                action: Action::Print { text },
                ..
            } => assert_eq!(text, "hello world\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn echo_n_suppresses_newline() {
        match verdict("echo -n hi") {
            Allow {
                action: Action::Print { text },
                ..
            } => assert_eq!(text, "hi"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn printf_renders_repeating_format() {
        match verdict(r"printf '%s\n' one two") {
            Allow {
                action: Action::Print { text },
                ..
            } => assert_eq!(text, "one\ntwo\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn printf_denies_unknown_directives() {
        assert!(matches!(verdict(r"printf '%q\n' foo"), Deny { .. }));
    }

    #[test]
    fn denies_unknown_binaries() {
        assert!(matches!(verdict("sudo make install"), Deny { .. }));
    }

    #[test]
    fn denies_rm_of_foreign_paths() {
        assert!(matches!(verdict("rm -rf /etc/passwd"), Deny { .. }));
    }

    #[test]
    fn allows_rm_of_owned_paths() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent/tool-staging");
        match verdict_with("rm -rf /tmp/iish-nonexistent/tool-staging", &session) {
            Allow {
                action:
                    Action::Remove {
                        recursive: true,
                        force: true,
                        ..
                    },
                ..
            } => {}
            other => panic!("expected allow/remove -rf, got {other:?}"),
        }
    }

    #[test]
    fn denies_chmod_of_foreign_paths() {
        assert!(matches!(verdict("chmod 755 /etc/passwd"), Deny { .. }));
    }

    #[test]
    fn allows_chmod_of_owned_paths() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent");
        match verdict_with("chmod +x /tmp/iish-nonexistent/tool", &session) {
            Allow {
                action:
                    Action::Chmod {
                        mode: Mode::AddBits(0o111),
                        ..
                    },
                ..
            } => {}
            other => panic!("expected allow/chmod +x, got {other:?}"),
        }
    }

    #[test]
    fn denies_curl_post() {
        assert!(matches!(
            verdict("curl -X POST https://example.com"),
            Deny { .. }
        ));
    }

    #[test]
    fn denies_curl_insecure() {
        assert!(matches!(
            verdict("curl -fsSLk https://example.com"),
            Deny { .. }
        ));
        assert!(matches!(
            verdict("curl --insecure https://example.com"),
            Deny { .. }
        ));
    }

    #[test]
    fn allows_curl_get_to_new_file() {
        match verdict("curl -fsSLo /tmp/iish-nonexistent-dl.tar.gz https://example.com/t.tar.gz") {
            Allow {
                action: Action::Fetch { url, output },
                ..
            } => {
                assert_eq!(url, "https://example.com/t.tar.gz");
                assert_eq!(
                    output,
                    FetchOutput::File(PathBuf::from("/tmp/iish-nonexistent-dl.tar.gz"))
                );
            }
            other => panic!("expected allow/fetch, got {other:?}"),
        }
    }

    #[test]
    fn curl_remote_name_uses_url_basename() {
        match verdict("curl -sSfLO https://example.com/pkg/tool-v1.tar.gz") {
            Allow {
                action:
                    Action::Fetch {
                        output: FetchOutput::File(path),
                        ..
                    },
                ..
            } => assert_eq!(path, state::normalize(Path::new("tool-v1.tar.gz"))),
            other => panic!("expected allow/fetch to file, got {other:?}"),
        }
    }

    #[test]
    fn curl_overwrite_of_existing_file_prompts() {
        assert!(matches!(
            verdict("curl -o /etc/hostname https://example.com/x"),
            Prompt { .. }
        ));
    }

    #[test]
    fn curl_to_stdout_is_allowed() {
        assert!(matches!(
            verdict("curl -fsSL https://example.com/install.sh"),
            Allow {
                action: Action::Fetch {
                    output: FetchOutput::Stdout,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn denies_curl_without_url() {
        assert!(matches!(verdict("curl -fsSL"), Deny { .. }));
        assert!(matches!(verdict("curl ftp://example.com/f"), Deny { .. }));
    }

    #[test]
    fn wget_defaults_to_url_basename() {
        match verdict("wget -q https://example.com/tool.tar.gz") {
            Allow {
                action:
                    Action::Fetch {
                        output: FetchOutput::File(path),
                        ..
                    },
                ..
            } => assert_eq!(path, state::normalize(Path::new("tool.tar.gz"))),
            other => panic!("expected allow/fetch to file, got {other:?}"),
        }
    }

    #[test]
    fn wget_denies_disabling_tls_checks() {
        assert!(matches!(
            verdict("wget --no-check-certificate https://example.com/t"),
            Deny { .. }
        ));
    }

    #[test]
    fn mkdir_of_new_dirs_is_allowed() {
        match verdict("mkdir -p /tmp/iish-nonexistent/a") {
            Allow {
                action: Action::MkDir { paths, parents },
                ..
            } => {
                assert!(parents);
                assert_eq!(paths, vec![PathBuf::from("/tmp/iish-nonexistent/a")]);
            }
            other => panic!("expected allow/mkdir, got {other:?}"),
        }
    }

    #[test]
    fn mkdir_p_on_existing_dir_is_a_noop() {
        assert!(matches!(
            verdict("mkdir -p /tmp"),
            Allow {
                action: Action::Noop,
                ..
            }
        ));
    }

    #[test]
    fn mkdir_without_p_on_existing_dir_is_denied() {
        assert!(matches!(verdict("mkdir /tmp"), Deny { .. }));
    }

    #[test]
    fn denies_piping_to_shell() {
        assert!(matches!(
            verdict("curl https://x.io/i.sh | sh"),
            Deny { .. }
        ));
    }

    #[test]
    fn denies_pipelines_generally() {
        assert!(matches!(verdict("cat foo | grep bar"), Deny { .. }));
    }

    #[test]
    fn denies_expansion() {
        assert!(matches!(verdict("echo $HOME"), Deny { .. }));
    }

    #[test]
    fn denies_control_flow_with_specific_reason() {
        match verdict("if true; then echo hi; fi") {
            Deny { reason } => assert!(reason.contains("if statements")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn denies_command_lists() {
        assert!(matches!(
            verdict("mkdir /tmp/a && mkdir /tmp/b"),
            Deny { .. }
        ));
    }

    #[test]
    fn denies_background_jobs() {
        assert!(matches!(verdict("echo hi &"), Deny { .. }));
    }
}
