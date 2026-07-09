//! iish — a safe interpreter for `curl … | sh` install scripts.
//!
//! Reads a bash script from a file argument or stdin, parses it with
//! brush-parser, and interprets it interleaved: each top-level
//! statement is evaluated against the installer safety policy with the
//! session ledger as it stands, then executed natively in Rust — never
//! by a real shell. Statements the policy can't vouch for are confirmed
//! on /dev/tty or refused; the first refusal aborts the run.

mod exec;
mod parser;
mod policy;
mod prompt;
mod state;

use policy::Verdict;
use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "usage: iish [--dry-run] [--yes|--no] [script.sh]
       curl -fsSL https://example.com/install.sh | iish

  --dry-run   report what every statement would do; execute nothing
  --yes       answer yes to every confirmation prompt
  --no        answer no to every confirmation prompt (asks become fatal)
  (reads the script from stdin when no file is given)";

fn main() -> ExitCode {
    let mut dry_run = false;
    let mut ask = prompt::AskMode::Tty;
    let mut path: Option<String> = None;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--yes" => ask = prompt::AskMode::AssumeYes,
            "--no" => ask = prompt::AskMode::AssumeNo,
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            a if a.starts_with('-') && a != "-" => {
                eprintln!("iish: unknown option `{a}`\n{USAGE}");
                return ExitCode::FAILURE;
            }
            _ if path.is_some() => {
                eprintln!("iish: more than one script given\n{USAGE}");
                return ExitCode::FAILURE;
            }
            _ => path = Some(arg),
        }
    }

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
        report(&items)
    } else {
        run(&items, ask)
    }
}

/// Execute the script statement by statement (interleaved model, see
/// PLAN.md): evaluate against the live ledger, confirm any ask, run the
/// compiled action natively, and abort on the first refusal or failure.
fn run(items: &[&parser::ast::CompoundListItem], ask: prompt::AskMode) -> ExitCode {
    let mut session = state::Session::new();

    for item in items {
        let statement = policy::evaluate_item(item, &session);
        let raw = &statement.raw;
        let action = match statement.verdict {
            Verdict::Deny { reason } => {
                eprintln!("iish: refusing `{raw}`: {reason}");
                eprintln!("iish: aborting; no later statement was run.");
                return ExitCode::FAILURE;
            }
            Verdict::Prompt { reason, action } => match prompt::confirm(ask, raw, &reason) {
                Ok(true) => action,
                Ok(false) => {
                    eprintln!("iish: `{raw}` declined ({reason}); aborting.");
                    return ExitCode::FAILURE;
                }
                Err(e) => {
                    eprintln!("iish: cannot confirm `{raw}`: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Verdict::Allow { action, .. } => action,
        };
        eprintln!("iish> {raw}");
        if let Err(e) = exec::execute(&action, &mut session) {
            eprintln!("iish: `{raw}` failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

/// `--dry-run`: print every statement's verdict without executing.
/// Creations are simulated in the ledger so that later statements are
/// judged as they would be in a live run.
fn report(items: &[&parser::ast::CompoundListItem]) -> ExitCode {
    let mut session = state::Session::new();
    let mut denied = 0usize;
    let mut asks = 0usize;

    println!("iish plan ({} statements):", items.len());
    for item in items {
        let statement = policy::evaluate_item(item, &session);
        let (tag, detail) = match &statement.verdict {
            Verdict::Allow { reason, action } => {
                exec::record_would_create(action, &mut session);
                ("ALLOW ", reason.clone())
            }
            Verdict::Prompt { reason, action } => {
                asks += 1;
                exec::record_would_create(action, &mut session);
                ("PROMPT", reason.clone())
            }
            Verdict::Deny { reason } => {
                denied += 1;
                ("DENY  ", reason.clone())
            }
        };
        println!("  [{tag}] {}", statement.raw);
        println!("           {detail}");
    }

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
