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
use exec::Out;
use policy::{Flow, Verdict};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: iish [options] [script.sh]
       curl -fsSL https://example.com/install.sh | iish

  --dry-run          report what every statement would do; execute nothing
  --analyze          scan every control-flow branch and summarize required capabilities
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
    let mut analyze = false;
    let mut ask = prompt::AskMode::Tty;
    let mut path: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut no_config = false;
    let mut cli = CliOverrides::default();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--analyze" => {
                dry_run = true;
                analyze = true;
            }
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
        report(&items, &config, analyze)
    } else {
        run(&items, ask, &config)
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("iish: {message}\n{USAGE}");
    ExitCode::FAILURE
}

/// How deep nested statement lists (a brace group, a function call, a
/// loop body, an `if`'s condition/branches, a command substitution) may
/// nest before `run`/`report` give up instead of recursing further.
/// Real installers nest a handful of levels deep at most; this exists
/// to turn a script that tries to blow the stack (e.g. `f() { f; }; f`,
/// a self-recursive function with no base case) into a clean refusal
/// instead of a crash.
const MAX_GROUP_DEPTH: usize = 200;

/// How many times a single `while`/`until` loop may iterate before iish
/// refuses to keep going: installers' loops walk argument lists and
/// retry counters, so a loop that reaches this bound is either runaway
/// (`while true; do :; done`) or something iish shouldn't be babysitting.
const MAX_LOOP_ITERATIONS: usize = 10_000;

/// Why execution stopped early. Two of these end the whole run; the
/// rest unwind to a boundary the runner intercepts:
///
/// * `Fatal` — a refusal, a declined prompt, or a genuine execution
///   error. Always propagates all the way to the top: iish's
///   "if we don't understand it, stop" posture. A sub-context (a
///   `$(…)` substitution, a `… | sh` sub-interpret) re-raises it.
/// * `Exit` — the script's *own* `exit N`. A sub-context absorbs it
///   (bash subshell semantics: the child's `exit` ends only the child)
///   and turns it into a status; at the top level it sets the run's
///   exit code.
/// * `Return`/`Break`/`Continue` — intercepted by `Verdict::Call` and
///   the loop runners respectively.
enum Abort {
    Fatal(ExitCode),
    Exit(u8),
    Return(i32),
    Break(u32),
    Continue(u32),
}

fn fail() -> Abort {
    Abort::Fatal(ExitCode::FAILURE)
}

/// Runs `$(command)` substitutions for word expansion (parser.rs's
/// `Substituter`): parse the inner text and run it through the very
/// same policy/prompt/execute loop as the enclosing script, with the
/// script's stdout captured — the capture becomes the substitution's
/// value. The inner statements run in condition mode: a non-zero exit
/// is recorded in `$?` (as bash does for a substitution) rather than
/// aborting the run, but a refusal or declined prompt still is fatal.
struct LiveSubstituter<'a> {
    ask: prompt::AskMode,
    config: &'a Config,
    depth: usize,
}

impl parser::Substituter for LiveSubstituter<'_> {
    fn substitute(
        &mut self,
        session: &mut state::Session,
        command: &str,
    ) -> Result<String, String> {
        let program = parser::parse(command)
            .map_err(|e| format!("could not parse command substitution `$({command})`: {e}"))?;
        let items = policy::items(&program);
        let mut buf = Vec::new();
        let result = run_items_inner(
            &items,
            self.ask,
            self.config,
            session,
            self.depth + 1,
            true,
            &mut Out::capture(&mut buf),
        );
        match result {
            Ok(status) => session.set_last_status(if status { 0 } else { 1 }),
            // The script's own `exit N` inside a substitution ends just
            // the substitution, like bash's subshell semantics; its
            // status lands in `$?`.
            Err(Abort::Exit(n)) => session.set_last_status(n as i32),
            Err(_) => {
                return Err(format!(
                    "command substitution `$({command})` was refused or failed; \
                     iish's reason is above"
                ))
            }
        }
        String::from_utf8(buf)
            .map_err(|_| format!("command substitution `$({command})` produced non-UTF-8 output"))
    }
}

/// Execute the script statement by statement (interleaved model, see
/// PLAN.md): evaluate against the live ledger and configuration,
/// confirm any ask, run the compiled action natively, and abort on the
/// first refusal or failure.
fn run(items: &[parser::ast::CompoundListItem], ask: prompt::AskMode, config: &Config) -> ExitCode {
    let mut session = state::Session::new();
    match run_items_inner(
        items,
        ask,
        config,
        &mut session,
        0,
        false,
        &mut Out::inherit(),
    ) {
        Ok(_) => ExitCode::SUCCESS,
        Err(Abort::Fatal(code)) => code,
        Err(Abort::Exit(n)) => ExitCode::from(n),
        Err(Abort::Return(_)) => {
            eprintln!("iish: `return` reached the top level with no function call to return from; aborting.");
            ExitCode::FAILURE
        }
        Err(Abort::Break(_)) | Err(Abort::Continue(_)) => {
            eprintln!(
                "iish: `break`/`continue` reached the top level with no loop to leave; aborting."
            );
            ExitCode::FAILURE
        }
    }
}

/// Evaluate `items` as an `if`/`while`/`until` condition: like the
/// plain walk, except a `Subprocess`/`Test`/... statement that "fails"
/// is recorded as `false` (returned once it's the last statement)
/// instead of aborting the whole run — exactly the exemption bash
/// itself grants the condition part of a compound command from its
/// usual (here, always-on) errexit posture. A `Deny`, a declined
/// prompt, or a genuine execution error still aborts unconditionally:
/// iish's "if we don't understand it, refuse" posture applies inside a
/// condition exactly as it does everywhere else.
fn run_condition(
    items: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    run_items_inner(items, ask, config, session, depth, true, out)
}

/// Shared implementation behind the plain and condition walks: runs
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
    out: &mut Out,
) -> Result<bool, Abort> {
    if depth > MAX_GROUP_DEPTH {
        eprintln!(
            "iish: nested groups/function calls are more than {MAX_GROUP_DEPTH} deep; aborting."
        );
        return Err(fail());
    }

    let mut status = true;
    for item in items {
        let statement = {
            let mut subst = LiveSubstituter { ask, config, depth };
            let mut ctx = parser::ExpandCtx {
                session,
                subst: &mut subst,
            };
            policy::evaluate_item(item, &mut ctx, config)
        };
        status = run_statement(
            statement.verdict,
            &statement.raw,
            ask,
            config,
            session,
            depth,
            in_condition,
            out,
        )?;
    }

    Ok(status)
}

/// Execute one already-evaluated verdict, returning its exit status.
/// Shared by `run_items_inner`'s per-statement loop and
/// `run_and_or_list`'s per-pipeline walk: a pipeline inside a `&&`/`||`
/// chain is evaluated and run exactly like a top-level statement, just
/// checked against the chain's running status instead of always running
/// unconditionally.
#[allow(clippy::too_many_arguments)]
fn run_statement(
    verdict: Verdict,
    raw: &str,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    in_condition: bool,
    out: &mut Out,
) -> Result<bool, Abort> {
    let status = match verdict {
        Verdict::Deny { reason } => {
            eprintln!("iish: refusing `{raw}`: {reason}");
            eprintln!("iish: aborting; no later statement was run.");
            return Err(fail());
        }
        Verdict::Group { statements } => {
            eprintln!("iish> {raw}");
            run_items_inner(
                &statements,
                ask,
                config,
                session,
                depth + 1,
                in_condition,
                out,
            )?
        }
        Verdict::Call { name, args, body } => {
            eprintln!("iish> {raw}");
            // The frame makes `args` the body's `$1`/`$@`/`$#`, scopes
            // its `local`s, and bounds its `return`. Popped on every
            // way out, including an abort passing through.
            session.push_frame(name, args);
            let result = run_items_inner(&body, ask, config, session, depth + 1, in_condition, out);
            session.pop_frame();
            match result {
                Err(Abort::Return(n)) => n == 0,
                other => other?,
            }
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
                out,
            )?;
            true
        }
        Verdict::For {
            variable,
            values,
            body,
        } => {
            eprintln!("iish> {raw}");
            run_for(
                &variable,
                values.as_deref(),
                &body,
                ask,
                config,
                session,
                depth,
                out,
            )?
        }
        Verdict::While {
            condition,
            body,
            until,
        } => {
            eprintln!("iish> {raw}");
            run_while(&condition, &body, until, ask, config, session, depth, out)?
        }
        Verdict::AndOrList { first, rest } => run_and_or_list(
            &first,
            &rest,
            raw,
            ask,
            config,
            session,
            depth,
            in_condition,
            out,
        )?,
        // `! pipeline`: run for status, report the negation. Never
        // trips the abort-on-failure posture — bash exempts `!`
        // pipelines from errexit entirely, negated result included.
        Verdict::Not { pipeline } => {
            !run_pipeline_for_status(&pipeline, ask, config, session, depth, out)?
        }
        Verdict::Pipe { stages } => {
            eprintln!("iish> {raw}");
            let status = run_pipe(&stages, raw, ask, config, session, depth, out)?;
            if !status && !in_condition {
                eprintln!("iish: `{raw}` exited with a non-zero status; aborting.");
                return Err(fail());
            }
            status
        }
        Verdict::PipeToShell { producer, shell } => {
            eprintln!("iish> {raw}");
            let status =
                run_pipe_to_shell(&producer, &shell, raw, ask, config, session, depth, out)?;
            if !status && !in_condition {
                eprintln!("iish: `{raw}` exited with a non-zero status; aborting.");
                return Err(fail());
            }
            status
        }
        Verdict::Subshell { statements } => {
            eprintln!("iish> {raw}");
            let status = run_subshell(&statements, ask, config, session, depth, out)?;
            if !status && !in_condition {
                eprintln!("iish: `{raw}` exited with a non-zero status; aborting.");
                return Err(fail());
            }
            status
        }
        Verdict::ControlFlow(flow) => {
            eprintln!("iish> {raw}");
            return Err(match flow {
                Flow::Return(n) => Abort::Return(n),
                Flow::Exit(n) => Abort::Exit(n),
                Flow::Break(n) => Abort::Break(n),
                Flow::Continue(n) => Abort::Continue(n),
            });
        }
        Verdict::Prompt { reason, action } => {
            let action = match prompt::confirm(ask, raw, &reason) {
                Ok(true) => action,
                Ok(false) => {
                    eprintln!("iish: `{raw}` declined ({reason}); aborting.");
                    return Err(fail());
                }
                Err(e) => {
                    eprintln!("iish: cannot confirm `{raw}`: {e}");
                    return Err(fail());
                }
            };
            eprintln!("iish> {raw}");
            execute_statement(&action, session, in_condition, raw, out)?
        }
        Verdict::Allow { action, .. } => {
            eprintln!("iish> {raw}");
            execute_statement(&action, session, in_condition, raw, out)?
        }
    };
    // `$?` tracks every statement as it completes, at whatever nesting
    // level, matching bash's continuously-updated view.
    session.set_last_status(if status { 0 } else { 1 });
    Ok(status)
}

/// `for NAME in words...`: expand the word list (field-wise: `"$@"` and
/// unquoted `$VAR` splitting behave — see parser.rs's `word_fields`),
/// then run the body once per field with NAME assigned. `break` and
/// `continue` unwind to here; `break 2`/`continue 2` pass through to
/// the next enclosing loop with the count decremented.
#[allow(clippy::too_many_arguments)]
fn run_for(
    variable: &str,
    values: Option<&[parser::ast::Word]>,
    body: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    let fields = match values {
        // `for NAME; do` iterates the positional parameters.
        None => session.positional().to_vec(),
        Some(words) => {
            let mut fields = Vec::new();
            for word in words {
                let expanded = {
                    let mut subst = LiveSubstituter { ask, config, depth };
                    let mut ctx = parser::ExpandCtx {
                        session,
                        subst: &mut subst,
                    };
                    parser::word_fields(word, &mut ctx)
                };
                match expanded {
                    Ok(mut f) => fields.append(&mut f),
                    Err(reason) => {
                        eprintln!("iish: refusing `for {variable} in ...`: {reason}");
                        eprintln!("iish: aborting; no later statement was run.");
                        return Err(fail());
                    }
                }
            }
            fields
        }
    };

    let mut status = true;
    for field in fields {
        session.set_variable(variable, field);
        match run_items_inner(body, ask, config, session, depth + 1, false, out) {
            Ok(s) => status = s,
            Err(Abort::Break(n)) => {
                if n > 1 {
                    return Err(Abort::Break(n - 1));
                }
                break;
            }
            Err(Abort::Continue(n)) => {
                if n > 1 {
                    return Err(Abort::Continue(n - 1));
                }
                status = true;
            }
            Err(other) => return Err(other),
        }
    }
    Ok(status)
}

/// One pipeline stage, resolved and confirmed: either a compiled
/// action, or a function call / brace group whose statements run with
/// the stage's captured stdout (`nvm_install_dir | sed ...`). A
/// statements stage doesn't consume the carried stdin — no native
/// statement reads stdin — matching how such stages are actually used
/// (as producers).
enum PipeStage {
    Action(exec::Action),
    Statements {
        frame: Option<(String, Vec<String>)>,
        body: Vec<parser::ast::CompoundListItem>,
    },
}

/// `first | second | ...`: run the stages sequentially, buffering each
/// stage's captured stdout as the next stage's stdin (see
/// `Verdict::Pipe` for why sequential-with-buffering). Each stage is
/// evaluated against the live session at its turn and must resolve to
/// a plain action — a compound command as a pipeline stage would need
/// subshell semantics iish doesn't have. The pipeline's status is the
/// last stage's; whether a false status aborts is the caller's call
/// (`run_statement`), same as any other statement.
#[allow(clippy::too_many_arguments)]
fn run_pipe(
    stages: &[parser::ast::Command],
    raw: &str,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    let mut carried: Option<Vec<u8>> = None;
    let mut status = true;
    let last = stages.len() - 1;
    for (i, stage) in stages.iter().enumerate() {
        let statement = {
            let mut subst = LiveSubstituter { ask, config, depth };
            let mut ctx = parser::ExpandCtx {
                session,
                subst: &mut subst,
            };
            policy::evaluate_pipe_stage(stage, &mut ctx, config)
        };
        let stage = match statement.verdict {
            Verdict::Allow { action, .. } => PipeStage::Action(action),
            Verdict::Prompt { reason, action } => {
                match prompt::confirm(ask, &statement.raw, &reason) {
                    Ok(true) => PipeStage::Action(action),
                    Ok(false) => {
                        eprintln!("iish: `{}` declined ({reason}); aborting.", statement.raw);
                        return Err(fail());
                    }
                    Err(e) => {
                        eprintln!("iish: cannot confirm `{}`: {e}", statement.raw);
                        return Err(fail());
                    }
                }
            }
            Verdict::Deny { reason } => {
                eprintln!("iish: refusing `{}`: {reason}", statement.raw);
                eprintln!("iish: aborting; no later statement was run.");
                return Err(fail());
            }
            Verdict::Call { name, args, body } => PipeStage::Statements {
                frame: Some((name, args)),
                body,
            },
            Verdict::Group { statements } => PipeStage::Statements {
                frame: None,
                body: statements,
            },
            _ => {
                eprintln!(
                    "iish: refusing `{}`: this construct is not implemented as a pipeline \
                     stage",
                    statement.raw
                );
                eprintln!("iish: aborting; no later statement was run.");
                return Err(fail());
            }
        };

        // The last stage writes to the pipeline's own destination;
        // earlier stages are captured for the next stage's stdin.
        let mut buf = Vec::new();
        let stdin = carried.take();
        status = if i == last {
            run_pipe_stage(stage, stdin, raw, ask, config, session, depth, out)?
        } else {
            let mut capture = Out::capture(&mut buf);
            let s = run_pipe_stage(stage, stdin, raw, ask, config, session, depth, &mut capture)?;
            carried = Some(buf);
            s
        };
    }
    Ok(status)
}

/// `producer … | sh`: the `curl … | sh` pattern, handled as a
/// `( ... )`: run `statements` in a subshell — against a snapshot of
/// the session's scope (variables, functions, frames, `set -u`) and the
/// working directory, both restored on the way out so the subshell's
/// changes don't leak (bash subshell isolation). Real filesystem effects
/// (created files) persist, since the ledger is not part of the
/// snapshot. The subshell's own `exit` ends only the subshell, becoming
/// its status; a refusal inside still aborts the whole run.
fn run_subshell(
    statements: &[parser::ast::CompoundListItem],
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    let scope = session.snapshot_scope();
    let cwd = std::env::current_dir().ok();
    // Run the body in status-computing mode: an ordinary non-zero exit
    // becomes the subshell's status (so `( … ) && x` / `( … ) || x`
    // behave), while a refusal still aborts. Whether the subshell's own
    // failure then aborts the parent is decided by the subshell's
    // context back in `run_statement`, matching bash's errexit rules.
    let result = run_items_inner(statements, ask, config, session, depth + 1, true, out);
    session.restore_scope(scope);
    if let Some(dir) = cwd {
        let _ = std::env::set_current_dir(dir);
    }
    match result {
        Ok(status) => Ok(status),
        // The subshell's own `exit N` ends only the subshell.
        Err(Abort::Exit(n)) => Ok(n == 0),
        // A refusal/error propagates to the top, as everywhere.
        Err(Abort::Fatal(code)) => Err(Abort::Fatal(code)),
        // `return`/`break`/`continue` can't cross a subshell boundary in
        // bash (it's a separate process); treat reaching here as a stop.
        Err(Abort::Return(_) | Abort::Break(_) | Abort::Continue(_)) => {
            eprintln!(
                "iish: a subshell used `return`/`break`/`continue` with nothing inside it to \
                 unwind to; aborting."
            );
            Err(fail())
        }
    }
}

/// `producer … | sh`: the `curl … | sh` pattern, handled as a
/// sub-context ("sub-iish") instead of refused — run `producer`,
/// capture its combined stdout, then parse that text and interpret it
/// through iish's own policy/runner in the same session. See
/// `Verdict::PipeToShell`. The sub-script's own `exit` ends only the
/// sub-context (subshell semantics: it becomes this pipeline's status);
/// a refusal inside it still aborts the whole run.
#[allow(clippy::too_many_arguments)]
fn run_pipe_to_shell(
    producer: &[parser::ast::Command],
    shell: &str,
    raw: &str,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    if depth > MAX_GROUP_DEPTH {
        eprintln!(
            "iish: `{shell}`-fed sub-interpreters are nested more than {MAX_GROUP_DEPTH} deep; \
             aborting."
        );
        return Err(fail());
    }

    // Run the producer stages, capturing everything they emit: that is
    // the script the shell would have run. A producer failure (a failed
    // download, a refused stage) propagates and aborts, exactly as it
    // would for any pipeline.
    let mut script_bytes = Vec::new();
    run_pipe(
        producer,
        raw,
        ask,
        config,
        session,
        depth,
        &mut Out::capture(&mut script_bytes),
    )?;

    let script = match String::from_utf8(script_bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("iish: the script piped into `{shell}` is not valid UTF-8; aborting.");
            return Err(fail());
        }
    };

    let program = match parser::parse(&script) {
        Ok(p) => p,
        Err(reason) => {
            eprintln!("iish: cannot parse the script piped into `{shell}`: {reason}");
            eprintln!("iish: aborting; no later statement was run.");
            return Err(fail());
        }
    };
    let items = policy::items(&program);
    if items.is_empty() {
        // An empty download (or a producer that printed nothing): the
        // shell would run nothing and succeed. So does iish.
        return Ok(true);
    }

    eprintln!(
        "iish: interpreting the script piped into `{shell}` myself (sub-iish); every statement \
         is vetted under the same policy"
    );
    match run_items_inner(&items, ask, config, session, depth + 1, false, out) {
        Ok(status) => Ok(status),
        // The second stage's own `exit N` ends only this sub-context.
        Err(Abort::Exit(n)) => Ok(n == 0),
        // A refusal or execution error still stops the whole run.
        Err(Abort::Fatal(code)) => Err(Abort::Fatal(code)),
        Err(Abort::Return(_) | Abort::Break(_) | Abort::Continue(_)) => {
            eprintln!(
                "iish: the script piped into `{shell}` used `return`/`break`/`continue` at its \
                 top level with nothing to unwind to; aborting."
            );
            Err(fail())
        }
    }
}

/// Run one resolved pipeline stage against `stage_out` (see `run_pipe`).
#[allow(clippy::too_many_arguments)]
fn run_pipe_stage(
    stage: PipeStage,
    stdin: Option<Vec<u8>>,
    raw: &str,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    stage_out: &mut Out,
) -> Result<bool, Abort> {
    match stage {
        PipeStage::Action(action) => {
            match exec::execute_piped(&action, session, stdin, stage_out) {
                Ok(s) => Ok(s),
                Err(e) => {
                    eprintln!("iish: `{raw}` failed: {e}");
                    Err(fail())
                }
            }
        }
        PipeStage::Statements { frame, body } => {
            let framed = frame.is_some();
            if let Some((name, args)) = frame {
                session.push_frame(name, args);
            }
            let result = run_items_inner(&body, ask, config, session, depth + 1, true, stage_out);
            if framed {
                session.pop_frame();
            }
            match result {
                Err(Abort::Return(n)) => Ok(n == 0),
                other => other,
            }
        }
    }
}

/// `while`/`until cond; do body; done`, with the same condition
/// exemption `if` gets and a hard iteration ceiling (see
/// `MAX_LOOP_ITERATIONS`).
#[allow(clippy::too_many_arguments)]
fn run_while(
    condition: &[parser::ast::CompoundListItem],
    body: &[parser::ast::CompoundListItem],
    until: bool,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    let mut status = true;
    for _ in 0..MAX_LOOP_ITERATIONS {
        let cond = run_condition(condition, ask, config, session, depth + 1, out)?;
        if cond == until {
            return Ok(status);
        }
        match run_items_inner(body, ask, config, session, depth + 1, false, out) {
            Ok(s) => status = s,
            Err(Abort::Break(n)) => {
                if n > 1 {
                    return Err(Abort::Break(n - 1));
                }
                return Ok(status);
            }
            Err(Abort::Continue(n)) => {
                if n > 1 {
                    return Err(Abort::Continue(n - 1));
                }
                status = true;
            }
            Err(other) => return Err(other),
        }
    }
    eprintln!("iish: loop exceeded {MAX_LOOP_ITERATIONS} iterations without finishing; aborting.");
    Err(fail())
}

/// `first && second || third ...`: run `first`, then walk `rest` left to
/// right, running each pipeline only when its own operator's
/// short-circuit condition holds (`&&` needs the status so far to be
/// success; `||` needs it to be failure). Every pipeline in the chain
/// runs in "report status, don't abort on failure" mode regardless of
/// `in_condition` — that's the entire reason `&&`/`||` exist, the same
/// exemption bash itself grants every pipeline before the last in such a
/// list. Only once the chain is exhausted does its own status get to
/// decide whether the usual abort-on-failure posture applies here — and
/// even then, only if the *grammatically last* pipeline is the one that
/// actually ran: real bash only lets a `&&`/`||` list's failure trip
/// errexit when the last pipeline in it both ran and failed, not merely
/// whenever the list's overall (possibly short-circuited-away) status
/// happens to be non-zero. `false && echo hi` survives `set -e` (`echo
/// hi`, the last pipeline, never ran); `true && false` does not (`false`
/// is last, and it ran).
#[allow(clippy::too_many_arguments)]
fn run_and_or_list(
    first: &parser::ast::Pipeline,
    rest: &[parser::ast::AndOr],
    raw: &str,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    in_condition: bool,
    out: &mut Out,
) -> Result<bool, Abort> {
    let mut status = run_pipeline_for_status(first, ask, config, session, depth, out)?;
    // Overwritten on every iteration, so after the loop this reflects
    // only the last entry's outcome — exactly the "was the last pipeline
    // in the whole chain the one that ran" question above. `rest` is
    // never empty here (see `Verdict::AndOrList`'s doc comment), so the
    // loop always runs at least once.
    let mut last_entry_ran = true;
    for and_or in rest {
        let (should_run, next) = match and_or {
            parser::ast::AndOr::And(next) => (status, next),
            parser::ast::AndOr::Or(next) => (!status, next),
        };
        last_entry_ran = should_run;
        if should_run {
            status = run_pipeline_for_status(next, ask, config, session, depth, out)?;
        }
    }

    if last_entry_ran && !status && !in_condition {
        eprintln!("iish: `{raw}` exited with a non-zero status; aborting.");
        return Err(fail());
    }
    Ok(status)
}

/// Evaluate and run one pipeline from inside a `&&`/`||` chain or a `!`
/// negation, always in status-returning mode (see `run_and_or_list`).
fn run_pipeline_for_status(
    pipeline: &parser::ast::Pipeline,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<bool, Abort> {
    let statement = {
        let mut subst = LiveSubstituter { ask, config, depth };
        let mut ctx = parser::ExpandCtx {
            session,
            subst: &mut subst,
        };
        policy::evaluate_pipeline_item(pipeline, &mut ctx, config)
    };
    run_statement(
        statement.verdict,
        &statement.raw,
        ask,
        config,
        session,
        depth,
        true,
        out,
    )
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
    out: &mut Out,
) -> Result<bool, Abort> {
    let result = if in_condition {
        exec::execute_returning_status(action, session, out)
    } else {
        exec::execute(action, session, out).map(|()| true)
    };
    match result {
        Ok(status) => Ok(status),
        Err(e) => {
            eprintln!("iish: `{raw}` failed: {e}");
            Err(fail())
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
#[allow(clippy::too_many_arguments)]
fn run_if(
    condition: &[parser::ast::CompoundListItem],
    then_branch: &[parser::ast::CompoundListItem],
    elses: Option<&[parser::ast::ElseClause]>,
    ask: prompt::AskMode,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    out: &mut Out,
) -> Result<(), Abort> {
    if depth > MAX_GROUP_DEPTH {
        eprintln!(
            "iish: nested groups/function calls are more than {MAX_GROUP_DEPTH} deep; aborting."
        );
        return Err(fail());
    }

    if run_condition(condition, ask, config, session, depth, out)? {
        return run_items_inner(then_branch, ask, config, session, depth, false, out).map(|_| ());
    }

    let Some(clauses) = elses else {
        return Ok(());
    };
    for clause in clauses {
        match &clause.condition {
            Some(elif_condition) => {
                if run_condition(&elif_condition.0, ask, config, session, depth, out)? {
                    return run_items_inner(
                        &clause.body.0,
                        ask,
                        config,
                        session,
                        depth,
                        false,
                        out,
                    )
                    .map(|_| ());
                }
            }
            None => {
                return run_items_inner(&clause.body.0, ask, config, session, depth, false, out)
                    .map(|_| ())
            }
        }
    }
    Ok(())
}

/// The reason `--dry-run` hands to expansion when a word needs a
/// `$(command)` resolved: dry-run executes nothing, so the value is
/// unknowable and the statement is reported as refused.
const DRY_RUN_SUBSTITUTION: &str =
    "command substitution is not resolved in --dry-run; run for real to expand it";

/// Reconstruct a compound condition for a branch report. Keeping the shell
/// spelling is intentional: it is the most useful form for a human or coding
/// agent deciding whether an OS-, architecture-, or environment-specific path
/// is in scope.
fn condition_text(items: &[parser::ast::CompoundListItem]) -> String {
    items
        .iter()
        .map(|item| item.0.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Best-effort platform labeling for conventional installer guards. This is
/// only an annotation; all branches are still analyzed, so an unfamiliar
/// spelling can never make analysis silently skip required behavior.
fn platform_annotation(guard: &str) -> &'static str {
    let guard = guard.to_ascii_lowercase();
    let windows = ["windows", "mingw", "msys", "cygwin", "win32"]
        .iter()
        .any(|token| guard.contains(token));
    let macos = ["darwin", "macos", "mac os", "osx"]
        .iter()
        .any(|token| guard.contains(token));
    let linux = guard.contains("linux");
    match (windows, macos, linux) {
        (true, false, false) => " [platform: Windows]",
        (false, true, false) => " [platform: macOS]",
        (false, false, true) => " [platform: Linux]",
        (false, false, false) => "",
        _ => " [platform: multiple OS values]",
    }
}

/// Name the concrete capability/tool boundary represented by an evaluated
/// action. These stable labels make `--analyze` output suitable as a feature
/// checklist without exposing Rust implementation details.
fn action_requirement(action: &exec::Action) -> String {
    use exec::Action;
    match action {
        Action::Noop | Action::Test { .. } => "builtin.control/test (native)".into(),
        Action::Print { .. } => "output.write (native)".into(),
        Action::MkDir { .. } => "filesystem.mkdir (native)".into(),
        Action::Touch { .. } => "filesystem.touch (native)".into(),
        Action::Remove { .. } => "filesystem.remove (native, ledger-restricted)".into(),
        Action::Chmod { .. } => "filesystem.chmod (native, ledger-restricted)".into(),
        Action::Fetch { .. } => "network.http_get (native)".into(),
        Action::AppendFile { .. } => {
            "filesystem.append_env_file (native, restricted grammar)".into()
        }
        Action::Sha256Sum { .. } | Action::Sha256Check { .. } => "crypto.sha256 (native)".into(),
        Action::Subprocess { name, .. } => format!("process.exec({name}) (generic subprocess)"),
        Action::DefineFunction { .. } => "shell.function_definition (native)".into(),
        Action::Copy { .. } => "filesystem.copy (native)".into(),
        Action::Assign { .. } | Action::DeclareLocal { .. } | Action::Unset { .. } => {
            "shell.variables (native)".into()
        }
        Action::Shift { .. } => "shell.positional_parameters (native)".into(),
        Action::SetNounset { .. } => "shell.option.nounset (native)".into(),
        Action::ProbeRead { .. } => "terminal.probe (native)".into(),
        Action::ChangeDir { .. } => "filesystem.chdir (native)".into(),
        Action::ReadLine { .. } => "terminal.read_line (native)".into(),
        Action::CommandLookup { .. } => "process.command_lookup (native)".into(),
    }
}

/// `--dry-run`: print every statement's verdict without executing.
/// Creations (and function definitions) are simulated in the ledger so
/// that later statements — including ones nested in a brace group or a
/// function call reached below — are judged as they would be in a live
/// run.
fn report(items: &[parser::ast::CompoundListItem], config: &Config, analyze: bool) -> ExitCode {
    let mut session = state::Session::new();
    let mut denied = 0usize;
    let mut asks = 0usize;

    if analyze {
        println!(
            "iish capability analysis ({} top-level statement(s)):",
            items.len()
        );
        println!("  All branches are scanned statically; no commands are executed.");
    } else {
        println!("iish plan ({} top-level statement(s)):", items.len());
    }
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
        let statement = {
            let mut subst = parser::RefuseSubstituter(DRY_RUN_SUBSTITUTION);
            let mut ctx = parser::ExpandCtx {
                session,
                subst: &mut subst,
            };
            policy::evaluate_item(item, &mut ctx, config)
        };
        report_verdict(statement, &indent, config, session, depth, denied, asks);
    }
}

/// Report one already-evaluated verdict, recursing into nested statement
/// lists (a brace group/function call/matched `case` arm, an `if`'s
/// condition and branches, a loop's condition and body, or a `&&`/`||`
/// chain's pipelines) at one deeper indent. Shared by `report_items`'s
/// per-statement loop and `report_and_or_list`'s per-pipeline walk.
fn report_verdict(
    statement: policy::Statement,
    indent: &str,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    denied: &mut usize,
    asks: &mut usize,
) {
    match statement.verdict {
        Verdict::Allow { reason, action } => {
            let requirement = action_requirement(&action);
            exec::record_would_create(&action, session);
            println!("{indent}  [ALLOW ] {}", statement.raw);
            println!("{indent}           {reason}");
            println!("{indent}           requires: {requirement}");
        }
        Verdict::Prompt { reason, action } => {
            *asks += 1;
            let requirement = action_requirement(&action);
            exec::record_would_create(&action, session);
            println!("{indent}  [PROMPT] {}", statement.raw);
            println!("{indent}           {reason}");
            println!(
                "{indent}           requires: {requirement}; supported with confirmation/config"
            );
        }
        Verdict::Deny { reason } => {
            *denied += 1;
            println!("{indent}  [DENY  ] {}", statement.raw);
            println!("{indent}           {reason}");
            println!("{indent}           requires: missing iish language/tool support");
        }
        Verdict::Group { statements } => {
            println!("{indent}  [GROUP ] {}", statement.raw);
            report_items(&statements, config, session, depth + 1, denied, asks);
        }
        Verdict::Call { name, args, body } => {
            // Simulate the call frame so the body's `$1`/`$@`/`local`
            // are judged as a live run would.
            println!("{indent}  [CALL  ] {}", statement.raw);
            session.push_frame(name, args);
            report_items(&body, config, session, depth + 1, denied, asks);
            session.pop_frame();
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
            let guard = condition_text(&condition);
            println!(
                "{indent}           condition: {guard}{}",
                platform_annotation(&guard)
            );
            report_items(&condition, config, session, depth + 1, denied, asks);
            println!("{indent}           then (when condition succeeds):");
            report_items(&then_branch, config, session, depth + 1, denied, asks);
            for clause in elses.iter().flatten() {
                match &clause.condition {
                    Some(elif_condition) => {
                        let guard = condition_text(&elif_condition.0);
                        println!(
                            "{indent}           elif condition: {guard}{}",
                            platform_annotation(&guard)
                        );
                        report_items(&elif_condition.0, config, session, depth + 1, denied, asks);
                        println!("{indent}           elif then (when preceding guards fail and this succeeds):");
                    }
                    None => println!("{indent}           else (when all preceding guards fail):"),
                }
                report_items(&clause.body.0, config, session, depth + 1, denied, asks);
            }
        }
        Verdict::For {
            variable,
            values,
            body,
        } => {
            // How many times (and with what values) the body runs is a
            // runtime question; report it once, with the loop variable
            // bound to the first statically-expandable value (or empty)
            // so the body's own expansions can be judged.
            println!("{indent}  [FOR   ] {}", statement.raw);
            let first_value = values
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .find_map(|word| {
                    let mut subst = parser::RefuseSubstituter(DRY_RUN_SUBSTITUTION);
                    let mut ctx = parser::ExpandCtx {
                        session,
                        subst: &mut subst,
                    };
                    parser::word_fields(word, &mut ctx)
                        .ok()
                        .and_then(|fields| fields.into_iter().next())
                })
                .unwrap_or_default();
            session.set_variable(variable, first_value);
            println!("{indent}           body (reported once):");
            report_items(&body, config, session, depth + 1, denied, asks);
        }
        Verdict::While {
            condition,
            body,
            until,
        } => {
            let label = if until { "[UNTIL ]" } else { "[WHILE ]" };
            println!("{indent}  {label} {}", statement.raw);
            let guard = condition_text(&condition);
            println!(
                "{indent}           condition: {guard}{}",
                platform_annotation(&guard)
            );
            report_items(&condition, config, session, depth + 1, denied, asks);
            println!("{indent}           body (reported once):");
            report_items(&body, config, session, depth + 1, denied, asks);
        }
        Verdict::AndOrList { first, rest } => {
            // Same posture as `If`: whether a later pipeline in the
            // chain would actually run depends on the real exit status
            // of what came before, which dry-run doesn't execute to
            // find out — so this reports every pipeline in the chain,
            // labeled with the operator that would decide whether it
            // runs, rather than guessing.
            println!("{indent}  [AND/OR] {}", statement.raw);
            report_pipeline(first, indent, config, session, depth, denied, asks);
            for and_or in rest {
                let (label, pipeline) = match and_or {
                    parser::ast::AndOr::And(p) => ("&&", p),
                    parser::ast::AndOr::Or(p) => ("||", p),
                };
                println!("{indent}           {label}");
                report_pipeline(pipeline, indent, config, session, depth, denied, asks);
            }
        }
        Verdict::Not { pipeline } => {
            println!("{indent}  [NOT   ] {}", statement.raw);
            report_pipeline(*pipeline, indent, config, session, depth, denied, asks);
        }
        Verdict::Pipe { stages } => {
            println!("{indent}  [PIPE  ] {}", statement.raw);
            for stage in stages {
                let stage_statement = {
                    let mut subst = parser::RefuseSubstituter(DRY_RUN_SUBSTITUTION);
                    let mut ctx = parser::ExpandCtx {
                        session,
                        subst: &mut subst,
                    };
                    policy::evaluate_pipe_stage(&stage, &mut ctx, config)
                };
                report_verdict(
                    stage_statement,
                    indent,
                    config,
                    session,
                    depth,
                    denied,
                    asks,
                );
            }
        }
        Verdict::PipeToShell { producer, shell } => {
            // Which statements the second stage actually contains is only
            // known once the producer really runs to fetch them, which
            // dry-run never does — so report the producer and note that
            // its output would be interpreted by iish (never handed to a
            // real `shell`), each statement vetted then.
            println!("{indent}  [PIPE→iish] {}", statement.raw);
            println!(
                "{indent}           the producer's output would be interpreted by iish itself \
                 (not `{shell}`), each statement vetted under this same policy:"
            );
            for stage in producer {
                let stage_statement = {
                    let mut subst = parser::RefuseSubstituter(DRY_RUN_SUBSTITUTION);
                    let mut ctx = parser::ExpandCtx {
                        session,
                        subst: &mut subst,
                    };
                    policy::evaluate_pipe_stage(&stage, &mut ctx, config)
                };
                report_verdict(
                    stage_statement,
                    indent,
                    config,
                    session,
                    depth,
                    denied,
                    asks,
                );
            }
        }
        Verdict::Subshell { statements } => {
            println!("{indent}  [SUBSHELL] {}", statement.raw);
            report_items(&statements, config, session, depth + 1, denied, asks);
        }
        Verdict::ControlFlow(_) => {
            println!("{indent}  [ALLOW ] {}", statement.raw);
            println!("{indent}           control flow only; runs nothing itself");
        }
    }
}

/// Evaluate and report one pipeline from inside a `&&`/`||` chain (see
/// `report_verdict`'s `AndOrList` arm).
fn report_pipeline(
    pipeline: parser::ast::Pipeline,
    indent: &str,
    config: &Config,
    session: &mut state::Session,
    depth: usize,
    denied: &mut usize,
    asks: &mut usize,
) {
    let statement = {
        let mut subst = parser::RefuseSubstituter(DRY_RUN_SUBSTITUTION);
        let mut ctx = parser::ExpandCtx {
            session,
            subst: &mut subst,
        };
        policy::evaluate_pipeline_item(&pipeline, &mut ctx, config)
    };
    report_verdict(statement, indent, config, session, depth, denied, asks);
}
