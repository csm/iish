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

use crate::config::{Config, NetworkPolicy, Verb};
use crate::exec::{Action, FetchOutput, Mode};
use crate::parser::{ast, literal_word};
use crate::state::{self, Session};
use std::fs;
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

/// Evaluate one top-level statement against the policy, the current
/// session ledger, and the effective configuration.
pub fn evaluate_item(
    item: &ast::CompoundListItem,
    session: &Session,
    config: &Config,
) -> Statement {
    Statement {
        raw: item.0.to_string(),
        verdict: evaluate_list_item(item, session, config),
    }
}

fn evaluate_list_item(item: &ast::CompoundListItem, session: &Session, config: &Config) -> Verdict {
    let ast::CompoundListItem(and_or, separator) = item;
    if matches!(separator, ast::SeparatorOperator::Async) {
        return deny("background jobs (`&`) are not implemented yet");
    }
    evaluate_and_or_list(and_or, session, config)
}

fn evaluate_and_or_list(list: &ast::AndOrList, session: &Session, config: &Config) -> Verdict {
    if !list.additional.is_empty() {
        return deny("command lists joined by `&&`/`||` are not implemented yet");
    }
    evaluate_pipeline(&list.first, session, config)
}

fn evaluate_pipeline(pipeline: &ast::Pipeline, session: &Session, config: &Config) -> Verdict {
    if pipeline.timed.is_some() {
        return deny("`time` is not implemented yet");
    }
    if pipeline.bang {
        return deny("`!` pipeline negation is not implemented yet");
    }
    match pipeline.seq.as_slice() {
        [] => deny("empty pipeline"),
        [only] => evaluate_command(only, session, config),
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
        .map(|w| is_shell_name(&w.value))
        .unwrap_or(false)
}

fn is_shell_name(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "zsh" | "dash" | "ksh")
}

fn evaluate_command(cmd: &ast::Command, session: &Session, config: &Config) -> Verdict {
    match cmd {
        ast::Command::Simple(sc) => evaluate_simple_command(sc, session, config),
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

fn evaluate_simple_command(
    cmd: &ast::SimpleCommand,
    session: &Session,
    config: &Config,
) -> Verdict {
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
    // The only redirect shape iish understands at all: a single `>>`
    // onto a plain filename. Anything else (fds, `<`, `>`, heredocs,
    // process substitution as a redirect target, more than one
    // redirect, ...) is denied below.
    let mut append_target: Option<&ast::Word> = None;
    let mut unsupported_redirect = false;
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
                ast::CommandPrefixOrSuffixItem::IoRedirect(r) => match r {
                    ast::IoRedirect::File(
                        None,
                        ast::IoFileRedirectKind::Append,
                        ast::IoFileRedirectTarget::Filename(target),
                    ) if append_target.is_none() => {
                        append_target = Some(target);
                    }
                    _ => unsupported_redirect = true,
                },
                ast::CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return deny("process substitution is not implemented yet");
                }
            }
        }
    }

    if unsupported_redirect {
        return deny(
            "redirection is only implemented for a single `>>` onto a plain filename \
             (see the env-file append grammar)",
        );
    }

    match append_target {
        None => evaluate_argv(&name, &args, session, config),
        Some(target) if matches!(name.as_str(), "echo" | "printf") => {
            evaluate_env_file_append(&name, &args, target, session, config)
        }
        Some(_) => deny(format!(
            "redirecting `{name}`'s output is not implemented yet"
        )),
    }
}

fn evaluate_argv(name: &str, args: &[String], session: &Session, config: &Config) -> Verdict {
    if config.command_override(name) == Some(Verb::Deny) {
        return deny(format!("`{name}` is denied by configuration"));
    }

    match name {
        "true" | ":" => allow("does nothing", Action::Noop),
        "echo" => evaluate_echo(args),
        "printf" => evaluate_printf(args),
        "mkdir" => evaluate_mkdir(args),
        "rm" => evaluate_rm(args, session),
        "chmod" => evaluate_chmod(args, session),
        "curl" => evaluate_curl(args, session, config),
        "wget" => evaluate_wget(args, session, config),
        "sha256sum" => evaluate_sha256sum(args, session),

        // A shell is exactly what iish exists to replace; no config
        // knob may reopen this escape hatch (see PLAN.md's "no pass
        // through to bash" principle).
        "sh" | "bash" | "zsh" | "dash" | "ksh" => deny(format!(
            "`{name}` is a shell; iish parses and vets scripts itself instead of handing them to one"
        )),

        // Shell builtins with no external binary: running them as a
        // subprocess would either find no binary to exec, or (`cd`,
        // `export`) run against a throwaway child process and have no
        // effect on iish's own state. Not implemented, and not eligible
        // for the subprocess tier below for that reason.
        "cd" | "export" | "source" | "." => {
            deny(format!("`{name}` is a shell builtin; iish does not implement it"))
        }

        // Everything else: real external binaries iish has no native
        // implementation for (cp, mv, tar, install, ln, sudo, package
        // managers, ...). Governed by the "subprocess" policy
        // (milestone 5, PLAN.md "Configuration") — allow/ask/deny,
        // globally or per command.
        other => evaluate_subprocess(other, args, session, config),
    }
}

/// The subprocess tier: commands iish has no native implementation for.
/// The already-parsed, literal argv is compiled into an `Action` that,
/// if allowed, execs it directly — never through a shell. This is also
/// how `sudo <cmd>` behaves until the sudo broker (milestone 4b) lands:
/// exactly the "degrade to per-command real sudo with fixed argv"
/// fallback PLAN.md's sudo-broker caveats describe.
fn evaluate_subprocess(name: &str, args: &[String], session: &Session, config: &Config) -> Verdict {
    let action = Action::Subprocess {
        name: name.to_string(),
        args: args.to_vec(),
    };
    let verb = config.command_override(name).unwrap_or_else(|| {
        if runs_a_created_path(name, session) {
            config.run_created
        } else {
            config.subprocess
        }
    });
    match verb {
        Verb::Deny => deny(format!("`{name}` is not on the installer allowlist")),
        Verb::Ask => prompt(
            format!("`{name}` is not natively implemented; run the literal command directly?"),
            action,
        ),
        Verb::Allow => allow(
            format!("`{name}` runs as a subprocess per configuration"),
            action,
        ),
    }
}

/// True if `name` looks like a path (not a bare `$PATH` lookup) to
/// something this run created earlier — e.g. a second-stage script the
/// install downloaded and is now executing.
fn runs_a_created_path(name: &str, session: &Session) -> bool {
    name.contains('/') && session.owns(&state::normalize(Path::new(name)))
}

/// rc/profile files iish will append to, matching PLAN.md's "Append to
/// shell env files" row. Only recognized when they sit directly in
/// `$HOME` — a same-named file elsewhere is not a shell startup file.
const ENV_FILE_NAMES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
];

fn is_recognized_env_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !ENV_FILE_NAMES.contains(&name) {
        return false;
    }
    match std::env::var("HOME") {
        Ok(home) => path.parent() == Some(Path::new(&home)),
        Err(_) => false,
    }
}

/// `echo`/`printf ... >> rcfile`: appends are allowed only onto a
/// recognized rc/profile file in `$HOME`, and only when every appended
/// line matches PLAN's restricted grammar (`export VAR=...`, `PATH=...`,
/// or `source`/`.` of a file this script created) — see
/// `check_env_file_grammar`. Governed by `config.env_file_append`.
fn evaluate_env_file_append(
    name: &str,
    args: &[String],
    target: &ast::Word,
    session: &Session,
    config: &Config,
) -> Verdict {
    let text = match render_output(name, args) {
        Ok(t) => t,
        Err(reason) => return deny(reason),
    };
    let path_str = match literal_word(target) {
        Ok(s) => s,
        Err(reason) => return deny(reason),
    };
    let path = state::normalize(Path::new(&path_str));

    if !is_recognized_env_file(&path) {
        return deny(format!(
            "`{}` is not a recognized shell rc/profile file in $HOME; env-file appends are \
             restricted to {}",
            path.display(),
            ENV_FILE_NAMES.join(", ")
        ));
    }
    if let Err(reason) = check_env_file_grammar(&text, session) {
        return deny(format!("append to `{}` refused: {reason}", path.display()));
    }

    let action = Action::AppendFile {
        path: path.clone(),
        text,
    };
    match config.env_file_append {
        Verb::Deny => deny(format!(
            "appending to `{}` is disabled by configuration",
            path.display()
        )),
        Verb::Ask => prompt(
            format!(
                "append to `{}` (matches the restricted env-file grammar)",
                path.display()
            ),
            action,
        ),
        Verb::Allow => allow(
            format!(
                "appends only lines matching the restricted env-file grammar to `{}`",
                path.display()
            ),
            action,
        ),
    }
}

/// Every non-blank line of an env-file append must be `export VAR=...`,
/// a `PATH=...` assignment, or `source`/`.` of a single path this script
/// already created — PLAN.md's restricted append grammar. Anything else
/// (conditionals, command substitution, arbitrary commands, ...) is
/// refused.
fn check_env_file_grammar(text: &str, session: &Session) -> Result<(), String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || is_export_assignment(line) || line.starts_with("PATH=") {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("source ")
            .or_else(|| line.strip_prefix(". "))
        {
            let target = rest.trim();
            if target.is_empty() || target.contains(char::is_whitespace) {
                return Err(format!(
                    "`{line}` is not a plain `source`/`.` of a single path"
                ));
            }
            let path = state::normalize(Path::new(target));
            if !session.owns(&path) {
                return Err(format!("`{target}` was not created by this script"));
            }
            continue;
        }
        return Err(format!(
            "`{line}` does not match the allowed grammar (export VAR=..., PATH=..., or \
             source/. of a file this script created)"
        ));
    }
    Ok(())
}

fn is_export_assignment(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("export ") else {
        return false;
    };
    let rest = rest.trim_start();
    let Some((var_name, _value)) = rest.split_once('=') else {
        return false;
    };
    !var_name.is_empty()
        && var_name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
        && var_name
            .chars()
            .all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// `sha256sum`: computes or verifies SHA-256 digests natively (PLAN.md's
/// "checksum verification" value-add). Restricted, like `rm`/`chmod`, to
/// paths this run created — installers use it to verify a download
/// against a checksums file they just fetched, not to read arbitrary
/// files on the system.
fn evaluate_sha256sum(args: &[String], session: &Session) -> Verdict {
    let mut check = false;
    let mut paths: Vec<&str> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-c" | "--check" => check = true,
            a if a.starts_with('-') => {
                return deny(format!("sha256sum option `{a}` is not supported"))
            }
            a => paths.push(a),
        }
    }

    if check {
        evaluate_sha256_check(&paths, session)
    } else {
        evaluate_sha256_compute(&paths, session)
    }
}

fn evaluate_sha256_compute(paths: &[&str], session: &Session) -> Verdict {
    if paths.is_empty() {
        return deny("sha256sum with no file");
    }
    let mut resolved = Vec::with_capacity(paths.len());
    for p in paths {
        let path = state::normalize(Path::new(p));
        if !session.owns(&path) {
            return deny(format!(
                "`{}` was not created by this script; sha256sum is limited to created paths",
                path.display()
            ));
        }
        resolved.push(path);
    }
    allow(
        "prints checksums only for paths this script created",
        Action::Sha256Sum { paths: resolved },
    )
}

fn evaluate_sha256_check(paths: &[&str], session: &Session) -> Verdict {
    let checklist = match paths {
        [one] => *one,
        [] => return deny("sha256sum -c with no checksums file"),
        _ => return deny("sha256sum -c supports exactly one checksums file"),
    };
    let checklist_path = state::normalize(Path::new(checklist));
    if !session.owns(&checklist_path) {
        return deny(format!(
            "`{}` was not created by this script; sha256sum -c is limited to created \
             checksums files",
            checklist_path.display()
        ));
    }
    let text = match fs::read_to_string(&checklist_path) {
        Ok(t) => t,
        Err(e) => return deny(format!("cannot read `{}`: {e}", checklist_path.display())),
    };
    let mut entries = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((hex, name)) = parse_checksum_line(line) else {
            return deny(format!(
                "`{}` line {}: not a `<sha256>  <path>` checksum line",
                checklist_path.display(),
                lineno + 1
            ));
        };
        let path = state::normalize(Path::new(name));
        if !session.owns(&path) {
            return deny(format!(
                "`{}` was not created by this script; sha256sum -c is limited to created paths",
                path.display()
            ));
        }
        entries.push((hex.to_string(), path));
    }
    if entries.is_empty() {
        return deny(format!(
            "`{}` contains no checksum lines",
            checklist_path.display()
        ));
    }
    allow(
        "verifies checksums only for paths this script created",
        Action::Sha256Check { entries },
    )
}

/// Parse one `sha256sum -c` line: a 64-character hex digest, then two
/// spaces (text mode) or a space and `*` (binary mode), then the path.
fn parse_checksum_line(line: &str) -> Option<(&str, &str)> {
    if line.len() < 66 {
        return None;
    }
    let (hex, rest) = line.split_at(64);
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let name = rest
        .strip_prefix("  ")
        .or_else(|| rest.strip_prefix(" *"))?;
    if name.is_empty() {
        return None;
    }
    Some((hex, name))
}

fn evaluate_echo(args: &[String]) -> Verdict {
    match render_echo(args) {
        Ok(text) => allow("prints output only", Action::Print { text }),
        Err(reason) => deny(reason),
    }
}

fn evaluate_printf(args: &[String]) -> Verdict {
    match render_output("printf", args) {
        Ok(text) => allow("prints output only", Action::Print { text }),
        Err(reason) => deny(reason),
    }
}

/// The text `echo`/`printf` would produce, shared between the plain
/// (stdout) and env-file-append (`>>`) evaluators.
fn render_output(name: &str, args: &[String]) -> Result<String, String> {
    match name {
        "echo" => render_echo(args),
        "printf" => {
            let (format, rest) = args
                .split_first()
                .ok_or_else(|| "printf with no format string".to_string())?;
            render_printf(format, rest)
        }
        other => Err(format!(
            "redirecting `{other}`'s output is not implemented yet"
        )),
    }
}

fn render_echo(args: &[String]) -> Result<String, String> {
    let mut newline = true;
    let mut rest = args;
    // Only leading flags count; after the first non-flag word, `-n` is
    // just text, as in real echo.
    while let Some(first) = rest.first() {
        match first.as_str() {
            "-n" => newline = false,
            "-E" => {} // no escape processing — already our behavior
            "-e" | "-ne" | "-en" => {
                return Err("echo -e escape processing is not implemented yet".into())
            }
            _ => break,
        }
        rest = &rest[1..];
    }
    let mut text = rest.join(" ");
    if newline {
        text.push('\n');
    }
    Ok(text)
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
fn evaluate_curl(args: &[String], session: &Session, config: &Config) -> Verdict {
    if config.network == NetworkPolicy::Deny {
        return deny("network access is disabled by configuration");
    }
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

    finish_fetch("curl", &urls, output, remote_name, session, config)
}

/// wget, same posture as curl: a small allowlist of flags, GET only,
/// fetched in-process.
fn evaluate_wget(args: &[String], session: &Session, config: &Config) -> Verdict {
    if config.network == NetworkPolicy::Deny {
        return deny("network access is disabled by configuration");
    }
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
    finish_fetch("wget", &urls, output, true, session, config)
}

/// Shared tail of curl/wget evaluation: validate the URL, resolve where
/// the body goes, and apply the overwrite policy.
fn finish_fetch(
    name: &str,
    urls: &[&str],
    output: Option<String>,
    remote_name: bool,
    session: &Session,
    config: &Config,
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
        FetchOutput::File(path) => match config.overwrite {
            Verb::Ask => prompt(
                format!(
                    "GET `{url}` would overwrite pre-existing `{}`",
                    path.display()
                ),
                action,
            ),
            Verb::Allow => allow(
                format!(
                    "GET `{url}` overwrites pre-existing `{}` (allowed by configuration)",
                    path.display()
                ),
                action,
            ),
            Verb::Deny => deny(format!(
                "GET `{url}` would overwrite pre-existing `{}`; overwriting is disabled by configuration",
                path.display()
            )),
        },
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
        verdict_with_config(line, session, &Config::default())
    }

    fn verdict_with_config(line: &str, session: &Session, config: &Config) -> Verdict {
        let program = parse(line).expect("should parse");
        let item = *items(&program).first().expect("should have one statement");
        evaluate_item(item, session, config).verdict
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
    fn unknown_binaries_ask_by_default() {
        // Milestone 5: PLAN.md's built-in default is "unlisted
        // subprocesses ⇒ ask", not a hard deny. This is also how
        // `sudo <cmd>` behaves pre-broker.
        match verdict("sudo make install") {
            Prompt {
                action: Action::Subprocess { name, args },
                ..
            } => {
                assert_eq!(name, "sudo");
                assert_eq!(args, vec!["make", "install"]);
            }
            other => panic!("expected prompt/subprocess, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_deny_config_denies_unknown_binaries() {
        let config = Config {
            subprocess: Verb::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config("sudo make install", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn subprocess_allow_config_allows_unknown_binaries() {
        let config = Config {
            subprocess: Verb::Allow,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config("uname -a", &Session::new(), &config),
            Allow {
                action: Action::Subprocess { .. },
                ..
            }
        ));
    }

    #[test]
    fn per_command_override_wins_over_subprocess_default() {
        let mut config = Config {
            subprocess: Verb::Allow,
            ..Config::default()
        };
        config.commands.insert("systemctl".to_string(), Verb::Deny);
        assert!(matches!(
            verdict_with_config("systemctl enable foo", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn config_deny_override_beats_native_command_logic() {
        let mut config = Config::default();
        config.commands.insert("curl".to_string(), Verb::Deny);
        assert!(matches!(
            verdict_with_config("curl https://example.com", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn shells_are_denied_even_if_configured_allow() {
        let mut config = Config {
            subprocess: Verb::Allow,
            ..Config::default()
        };
        config.commands.insert("bash".to_string(), Verb::Allow);
        assert!(matches!(
            verdict_with_config("bash script.sh", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn shell_builtins_are_denied_even_if_configured_allow() {
        let config = Config {
            subprocess: Verb::Allow,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config("cd /tmp", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn recognized_but_unimplemented_binaries_use_subprocess_tier() {
        let config = Config {
            subprocess: Verb::Allow,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config("cp a b", &Session::new(), &config),
            Allow {
                action: Action::Subprocess { .. },
                ..
            }
        ));
    }

    #[test]
    fn network_deny_config_denies_curl_and_wget() {
        let config = Config {
            network: NetworkPolicy::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config("curl https://example.com", &Session::new(), &config),
            Deny { .. }
        ));
        assert!(matches!(
            verdict_with_config("wget https://example.com", &Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn overwrite_allow_config_skips_the_prompt() {
        let config = Config {
            overwrite: Verb::Allow,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                "curl -o /etc/hostname https://example.com/x",
                &Session::new(),
                &config
            ),
            Allow {
                action: Action::Fetch { .. },
                ..
            }
        ));
    }

    #[test]
    fn overwrite_deny_config_refuses_outright() {
        let config = Config {
            overwrite: Verb::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                "curl -o /etc/hostname https://example.com/x",
                &Session::new(),
                &config
            ),
            Deny { .. }
        ));
    }

    #[test]
    fn run_created_policy_governs_executing_a_downloaded_path() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent-stage2");
        let config = Config {
            run_created: Verb::Allow,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                "/tmp/iish-nonexistent-stage2/install.sh --now",
                &session,
                &config
            ),
            Allow {
                action: Action::Subprocess { .. },
                ..
            }
        ));
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

    fn home_rc(name: &str) -> String {
        let home = std::env::var("HOME").expect("test environment should have $HOME set");
        format!("{home}/{name}")
    }

    #[test]
    fn env_file_append_prompts_for_export_line() {
        let rc = home_rc(".bashrc");
        let script = format!("echo 'export PATH=\"/opt/tool/bin:$PATH\"' >> {rc}");
        match verdict(&script) {
            Prompt {
                action: Action::AppendFile { path, text },
                ..
            } => {
                assert_eq!(path, PathBuf::from(&rc));
                assert_eq!(text, "export PATH=\"/opt/tool/bin:$PATH\"\n");
            }
            other => panic!("expected prompt/append, got {other:?}"),
        }
    }

    #[test]
    fn env_file_append_prompts_for_bare_path_assignment() {
        let rc = home_rc(".zshrc");
        match verdict(&format!("echo 'PATH=/opt/tool/bin:$PATH' >> {rc}")) {
            Prompt {
                action: Action::AppendFile { .. },
                ..
            } => {}
            other => panic!("expected prompt/append, got {other:?}"),
        }
    }

    #[test]
    fn env_file_append_allows_source_of_owned_file_when_configured() {
        let mut session = Session::new();
        session.record_created("/opt/tool/env.sh");
        let rc = home_rc(".profile");
        let config = Config {
            env_file_append: Verb::Allow,
            ..Config::default()
        };
        match verdict_with_config(
            &format!("echo 'source /opt/tool/env.sh' >> {rc}"),
            &session,
            &config,
        ) {
            Allow {
                action: Action::AppendFile { .. },
                ..
            } => {}
            other => panic!("expected allow/append, got {other:?}"),
        }
    }

    #[test]
    fn env_file_append_denies_source_of_unowned_file() {
        let rc = home_rc(".profile");
        assert!(matches!(
            verdict(&format!("echo 'source /etc/evil.sh' >> {rc}")),
            Deny { .. }
        ));
    }

    #[test]
    fn env_file_append_denies_arbitrary_commands() {
        let rc = home_rc(".bashrc");
        assert!(matches!(
            verdict(&format!("echo 'rm -rf /' >> {rc}")),
            Deny { .. }
        ));
    }

    #[test]
    fn env_file_append_denies_unrecognized_target() {
        assert!(matches!(
            verdict("echo 'export FOO=bar' >> /etc/passwd"),
            Deny { .. }
        ));
    }

    #[test]
    fn env_file_append_denies_second_redirect() {
        let rc = home_rc(".bashrc");
        assert!(matches!(
            verdict(&format!("echo 'export FOO=bar' >> {rc} >> {rc}")),
            Deny { .. }
        ));
    }

    #[test]
    fn env_file_append_config_deny_refuses_even_valid_grammar() {
        let rc = home_rc(".bashrc");
        let config = Config {
            env_file_append: Verb::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                &format!("echo 'export FOO=bar' >> {rc}"),
                &Session::new(),
                &config
            ),
            Deny { .. }
        ));
    }

    #[test]
    fn env_file_append_config_ask_prompts() {
        let rc = home_rc(".bashrc");
        let config = Config {
            env_file_append: Verb::Ask,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                &format!("echo 'export FOO=bar' >> {rc}"),
                &Session::new(),
                &config
            ),
            Prompt { .. }
        ));
    }

    #[test]
    fn other_redirects_are_still_denied() {
        assert!(matches!(
            verdict("echo hi > /tmp/iish-nonexistent"),
            Deny { .. }
        ));
        assert!(matches!(verdict("mkdir /tmp/a 2> /tmp/err"), Deny { .. }));
    }

    #[test]
    fn sha256sum_compute_denies_unowned_file() {
        assert!(matches!(verdict("sha256sum /etc/passwd"), Deny { .. }));
    }

    #[test]
    fn sha256sum_compute_allows_owned_file() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent-dl/tool.tar.gz");
        match verdict_with("sha256sum /tmp/iish-nonexistent-dl/tool.tar.gz", &session) {
            Allow {
                action: Action::Sha256Sum { paths },
                ..
            } => assert_eq!(
                paths,
                vec![PathBuf::from("/tmp/iish-nonexistent-dl/tool.tar.gz")]
            ),
            other => panic!("expected allow/sha256sum, got {other:?}"),
        }
    }

    #[test]
    fn sha256sum_check_denies_unowned_checksums_file() {
        assert!(matches!(
            verdict("sha256sum -c /etc/checksums.txt"),
            Deny { .. }
        ));
    }

    #[test]
    fn sha256sum_check_allows_owned_checklist_with_owned_entries() {
        let dir = std::env::temp_dir().join(format!("iish-policy-sha256-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("tool.bin");
        let checklist = dir.join("tool.bin.sha256");
        std::fs::write(&target, b"payload").unwrap();
        std::fs::write(
            &checklist,
            format!(
                "{}  {}\n",
                "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
                target.display()
            ),
        )
        .unwrap();
        let mut session = Session::new();
        session.record_created(&checklist);
        session.record_created(&target);

        match verdict_with(&format!("sha256sum -c {}", checklist.display()), &session) {
            Allow {
                action: Action::Sha256Check { entries },
                ..
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].1, target);
            }
            other => panic!("expected allow/sha256check, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sha256sum_check_denies_unowned_entry_path() {
        let dir =
            std::env::temp_dir().join(format!("iish-policy-sha256-foreign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let checklist = dir.join("checksums.txt");
        std::fs::write(&checklist, format!("{}  /etc/passwd\n", "0".repeat(64))).unwrap();
        let mut session = Session::new();
        session.record_created(&checklist);

        assert!(matches!(
            verdict_with(&format!("sha256sum -c {}", checklist.display()), &session),
            Deny { .. }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
