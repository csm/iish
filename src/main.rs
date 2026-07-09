//! iish — a safe interpreter for `curl … | sh` install scripts.
//!
//! Reads a bash script from a file argument or stdin, parses it with
//! brush-parser, and interprets it interleaved: each top-level
//! statement is evaluated against the installer safety policy — built-in
//! defaults layered under a config file and CLI overrides (PLAN.md
//! "Configuration") — with the session ledger as it stands, then
//! executed natively in Rust — never by a real shell. Statements the
//! policy can't vouch for are confirmed on /dev/tty or refused; the
//! first refusal aborts the run.

mod config;
mod exec;
mod parser;
mod policy;
mod prompt;
mod state;

use config::{CliOverrides, Config, NetworkPolicy, Verb};
use policy::Verdict;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: iish [options] [script.sh]
       curl -fsSL https://example.com/install.sh | iish

  --dry-run          report what every statement would do; execute nothing
  --yes              answer yes to every confirmation prompt
  --no               answer no to every confirmation prompt (asks become fatal)
  --allow NAME       always allow this command (subprocess tier)
  --deny NAME        always deny this command
  --subprocess=VERB  default for commands with no native support: allow|ask|deny
  --overwrite=VERB   default for overwriting pre-existing files: allow|ask|deny
  --network=POLICY   get-only|deny
  --config PATH      use this config file instead of ~/.config/iish/config.toml
  --no-config        ignore any config file
  (reads the script from stdin when no file is given)";

fn main() -> ExitCode {
    let mut dry_run = false;
    let mut ask = prompt::AskMode::Tty;
    let mut path: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut no_config = false;
    let mut cli = CliOverrides::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--yes" => ask = prompt::AskMode::AssumeYes,
            "--no" => ask = prompt::AskMode::AssumeNo,
            "--no-config" => no_config = true,
            "--config" => match args.next() {
                Some(v) => config_path = Some(v),
                None => return usage_error("--config needs a path"),
            },
            "--allow" => match args.next() {
                Some(name) => {
                    cli.commands.insert(name, Verb::Allow);
                }
                None => return usage_error("--allow needs a command name"),
            },
            "--deny" => match args.next() {
                Some(name) => {
                    cli.commands.insert(name, Verb::Deny);
                }
                None => return usage_error("--deny needs a command name"),
            },
            a if a.starts_with("--subprocess=") => match Verb::parse(&a["--subprocess=".len()..]) {
                Ok(v) => cli.subprocess = Some(v),
                Err(e) => return usage_error(&format!("--subprocess: {e}")),
            },
            a if a.starts_with("--overwrite=") => match Verb::parse(&a["--overwrite=".len()..]) {
                Ok(v) => cli.overwrite = Some(v),
                Err(e) => return usage_error(&format!("--overwrite: {e}")),
            },
            a if a.starts_with("--network=") => {
                match NetworkPolicy::parse(&a["--network=".len()..]) {
                    Ok(v) => cli.network = Some(v),
                    Err(e) => return usage_error(&format!("--network: {e}")),
                }
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            a if a.starts_with('-') && a != "-" => {
                return usage_error(&format!("unknown option `{a}`"));
            }
            _ if path.is_some() => {
                return usage_error("more than one script given");
            }
            _ => path = Some(arg),
        }
    }

    // An explicit `--config` always wins; otherwise `--no-config` skips
    // the default lookup, and by default we look under
    // ~/.config/iish/config.toml (see `Config::default_path`).
    let config_path = match config_path {
        Some(p) => Some(PathBuf::from(p)),
        None if no_config => None,
        None => Config::default_path(),
    };
    let config = match Config::load(config_path.as_deref(), cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("iish: {e}");
            return ExitCode::FAILURE;
        }
    };

    let script = match path.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("iish: failed to read stdin: {e}");
                return ExitCode::FAILURE;
            }
            buf
        }
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("iish: cannot read `{path}`: {e}");
                return ExitCode::FAILURE;
            }
        },
    };

    let program = match parser::parse(&script) {
        Ok(program) => program,
        Err(reason) => {
            eprintln!("iish: could not parse script: {reason}");
            return ExitCode::FAILURE;
        }
    };

    let items = policy::items(&program);
    if items.is_empty() {
        eprintln!("iish: script contains no commands");
        return ExitCode::FAILURE;
    }

    if dry_run {
        report(&items, &config)
    } else {
        run(&items, ask, &config)
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("iish: {message}\n{USAGE}");
    ExitCode::FAILURE
}

/// How deep `Verdict::Group`/`Verdict::If` (a brace group, a call into a
/// previously defined function, or an `if`'s condition/branches) may
/// nest before `run`/`report` give up instead of recursing further. Real
/// installers nest a handful of levels deep at most; this exists to turn
/// a script that tries to blow the stack (e.g. `f() { f; }; f`, a
/// self-recursive function with no base case, or `while true` if that
/// were implemented) into a clean refusal instead of a crash.
const MAX_GROUP_DEPTH: usize = 200;

/// Execute the script statement by statement (interleaved model, see
/// PLAN.md): evaluate against the live ledger and configuration,
/// confirm any ask, run the compiled action natively, and abort on the
/// first refusal or failure. A `Verdict::Group` (brace group or
/// function call) recurses into its own statement list against the
/// same live session, rather than compiling to a single `Action`.
fn run(items: &[parser::ast::CompoundListItem], ask: prompt::AskMode, config: &Config) -> ExitCode {
    let mut session = state::Session::new();
    match run_items(items, ask, config, &mut session, 0) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// `Ok(())` once every statement in `items` ran; `Err(code)` the moment
/// one is refused, declined, or fails — the caller (possibly a
/// recursive call for an enclosing group) must stop at exactly that
/// point too, so no later statement runs after an abort.
fn run_items(
    items: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
) -> Result<(), ExitCode> {
    run_items_inner(items, ask, config, session, depth, false).map(|_| ())
}

/// Evaluate `items` as an `if`/`while`/`until` condition: like
/// `run_items`, except a `Subprocess`/`Test` statement that "fails" is
/// recorded as `false` (returned once it's the last statement) instead
/// of aborting the whole run — exactly the exemption bash itself grants
/// the condition part of a compound command from its usual (here,
/// always-on) errexit posture. A `Deny`, a declined prompt, or a genuine
/// execution error (as opposed to an ordinary non-zero exit) still
/// aborts unconditionally: iish's "if we don't understand it, refuse"
/// posture applies inside a condition exactly as it does everywhere else.
fn run_condition(
    items: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
) -> Result<bool, ExitCode> {
    run_items_inner(items, ask, config, session, depth, true)
}

/// Shared implementation behind `run_items` and `run_condition`: walks
/// `items` in order, returning the exit status of the last one (`true`
/// if `items` is empty, matching a no-op condition). `in_condition`
/// controls only whether a statement's own non-zero/false status aborts
/// the run or is simply the value returned for the caller to branch on.
fn run_items_inner(
    items: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    in_condition: bool,
) -> Result<bool, ExitCode> {
    if depth > MAX_GROUP_DEPTH {
        eprintln!(
            "iish: nested groups/function calls are more than {MAX_GROUP_DEPTH} deep; aborting."
        );
        return Err(ExitCode::FAILURE);
    }

    let mut status = true;
    for item in items {
        let statement = policy::evaluate_item(item, session, config);
        let raw = &statement.raw;
        status = match statement.verdict {
            Verdict::Deny { reason } => {
                eprintln!("iish: refusing `{raw}`: {reason}");
                eprintln!("iish: aborting; no later statement was run.");
                return Err(ExitCode::FAILURE);
            }
            Verdict::Group { statements } => {
                eprintln!("iish> {raw}");
                run_items_inner(&statements, ask, config, session, depth + 1, in_condition)?
            }
            Verdict::If {
                condition,
                then_branch,
                elses,
            } => {
                eprintln!("iish> {raw}");
                run_if(
                    &condition,
                    &then_branch,
                    elses.as_deref(),
                    ask,
                    config,
                    session,
                    depth + 1,
                )?;
                true
            }
            Verdict::Prompt { reason, action } => {
                let action = match prompt::confirm(ask, raw, &reason) {
                    Ok(true) => action,
                    Ok(false) => {
                        eprintln!("iish: `{raw}` declined ({reason}); aborting.");
                        return Err(ExitCode::FAILURE);
                    }
                    Err(e) => {
                        eprintln!("iish: cannot confirm `{raw}`: {e}");
                        return Err(ExitCode::FAILURE);
                    }
                };
                eprintln!("iish> {raw}");
                execute_statement(&action, session, in_condition, raw)?
            }
            Verdict::Allow { action, .. } => {
                eprintln!("iish> {raw}");
                execute_statement(&action, session, in_condition, raw)?
            }
        };
    }

    Ok(status)
}

/// Run one already-confirmed action, returning its exit status. Outside
/// a condition this is exactly the previous fail-fast behavior (any
/// `Err` — including a non-zero subprocess exit or false test — aborts);
/// inside one, a non-zero/false result is reported back instead of
/// aborting, per `run_condition`'s doc comment.
fn execute_statement(
    action: &exec::Action,
    session: &mut state::Session,
    in_condition: bool,
    raw: &str,
) -> Result<bool, ExitCode> {
    let result = if in_condition {
        exec::execute_returning_status(action, session)
    } else {
        exec::execute(action, session).map(|()| true)
    };
    match result {
        Ok(status) => Ok(status),
        Err(e) => {
            eprintln!("iish: `{raw}` failed: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// `if condition; then then_branch; elif ...; else ...; fi`: evaluate
/// `condition` (with real side effects — it's run exactly like a
/// top-level statement list, just exempted from aborting on its own
/// non-zero/false exit), then recurse into whichever branch it selects.
/// `elses` is the AST's own flat list of `elif`/`else` clauses; each
/// `elif`'s condition is checked in turn, and the first clause with no
/// condition at all (a plain `else`) always matches.
fn run_if(
    condition: &[parser::ast::CompoundListItem],
    then_branch: &[parser::ast::CompoundListItem],
    elses: Option<&[parser::ast::ElseClause]>,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
) -> Result<(), ExitCode> {
    if depth > MAX_GROUP_DEPTH {
        eprintln!(
            "iish: nested groups/function calls are more than {MAX_GROUP_DEPTH} deep; aborting."
        );
        return Err(ExitCode::FAILURE);
    }

    if run_condition(condition, ask, config, session, depth)? {
        return run_items_inner(then_branch, ask, config, session, depth, false).map(|_| ());
    }

    let Some(clauses) = elses else {
        return Ok(());
    };
    for clause in clauses {
        match &clause.condition {
            Some(elif_condition) => {
                if run_condition(&elif_condition.0, ask, config, session, depth)? {
                    return run_items_inner(&clause.body.0, ask, config, session, depth, false)
                        .map(|_| ());
                }
            }
            None => {
                return run_items_inner(&clause.body.0, ask, config, session, depth, false)
                    .map(|_| ())
            }
        }
    }
    Ok(())
}

/// `--dry-run`: print every statement's verdict without executing.
/// Creations (and function definitions) are simulated in the ledger so
/// that later statements — including ones nested in a brace group or a
/// function call reached below — are judged as they would be in a live
/// run.
fn report(items: &[parser::ast::CompoundListItem], config: &Config) -> ExitCode {
    let mut session = state::Session::new();
    let mut denied = 0usize;
    let mut asks = 0usize;

    println!("iish plan ({} top-level statement(s)):", items.len());
    report_items(items, config, &mut session, 0, &mut denied, &mut asks);

    if denied > 0 {
        println!("\n{denied} statement(s) would be refused; nothing was executed.");
        ExitCode::FAILURE
    } else if asks > 0 {
        println!("\nAll statements pass policy; {asks} would ask for confirmation.");
        ExitCode::SUCCESS
    } else {
        println!("\nAll statements pass policy.");
        ExitCode::SUCCESS
    }
}

fn report_items(
    items: &[parser::ast::CompoundListItem],
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    denied: &mut usize,
    asks: &mut usize,
) {
    if depth > MAX_GROUP_DEPTH {
        println!("  [DENY  ] (nested groups/function calls are more than {MAX_GROUP_DEPTH} deep)");
        *denied += 1;
        return;
    }
    let indent = "  ".repeat(depth);

    for item in items {
        let statement = policy::evaluate_item(item, session, config);
        match statement.verdict {
            Verdict::Allow { reason, action } => {
                exec::record_would_create(&action, session);
                println!("{indent}  [ALLOW ] {}", statement.raw);
                println!("{indent}           {reason}");
            }
            Verdict::Prompt { reason, action } => {
                *asks += 1;
                exec::record_would_create(&action, session);
                println!("{indent}  [PROMPT] {}", statement.raw);
                println!("{indent}           {reason}");
            }
            Verdict::Deny { reason } => {
                *denied += 1;
                println!("{indent}  [DENY  ] {}", statement.raw);
                println!("{indent}           {reason}");
            }
            Verdict::Group { statements } => {
                println!("{indent}  [GROUP ] {}", statement.raw);
                report_items(&statements, config, session, depth + 1, denied, asks);
            }
            Verdict::If {
                condition,
                then_branch,
                elses,
            } => {
                // Which branch actually runs can depend on a subprocess's
                // real exit code, which dry-run never executes to find
                // out — so, unlike every other statement here, this
                // reports the condition and *every* branch rather than
                // picking one; PLAN.md's "best-effort static report".
                println!("{indent}  [IF    ] {}", statement.raw);
                println!("{indent}           condition:");
                report_items(&condition, config, session, depth + 1, denied, asks);
                println!("{indent}           then:");
                report_items(&then_branch, config, session, depth + 1, denied, asks);
                for clause in elses.iter().flatten() {
                    match &clause.condition {
                        Some(elif_condition) => {
                            println!("{indent}           elif condition:");
                            report_items(
                                &elif_condition.0,
                                config,
                                session,
                                depth + 1,
                                denied,
                                asks,
                            );
                            println!("{indent}           elif then:");
                        }
                        None => println!("{indent}           else:"),
                    }
                    report_items(&clause.body.0, config, session, depth + 1, denied, asks);
                }
            }
        }
    }
}
