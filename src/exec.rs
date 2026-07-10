//! Native execution of allowed operations (milestone 4).
//!
//! Nothing here shells out. The policy compiles each statement it
//! passes into an [`Action`]; this module gives every action a Rust
//! implementation that consults and updates the [`Session`] ledger:
//! directory and file creation records ownership, deletion re-checks
//! it, and fetches are performed by iish's own GET-only HTTP client
//! rather than a real curl/wget binary. Executing an action never
//! re-interprets shell syntax.
//!
//! Every entry point takes an [`Out`]: where the *script's* stdout goes.
//! Normally that's iish's own stdout, but inside a `$(command)`
//! substitution the runner captures it into a buffer instead — that
//! buffer becomes the substitution's value.

use crate::parser::ast;
use crate::state::Session;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where the script's stdout is going: through to iish's own stdout, or
/// captured into a buffer (the value of a `$(command)` substitution).
/// The script's stderr is never captured — bash substitutions don't
/// capture stderr either (short of `2>&1`, handled per-command).
pub struct Out<'a> {
    capture: Option<&'a mut Vec<u8>>,
}

impl<'a> Out<'a> {
    /// Script stdout passes straight through to iish's stdout.
    pub fn inherit() -> Out<'static> {
        Out { capture: None }
    }

    /// Script stdout accumulates in `buf` (command substitution).
    pub fn capture(buf: &'a mut Vec<u8>) -> Out<'a> {
        Out { capture: Some(buf) }
    }

    pub fn is_capturing(&self) -> bool {
        self.capture.is_some()
    }
}

impl io::Write for Out<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.capture {
            Some(vec) => vec.write(buf),
            None => io::stdout().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.capture {
            Some(vec) => vec.flush(),
            None => io::stdout().flush(),
        }
    }
}

/// Where a command's stdout was redirected by the statement itself:
/// nowhere special, `> /dev/null`, or `>&2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StdoutDest {
    #[default]
    Inherit,
    Null,
    Stderr,
}

/// Where a command's stderr was redirected: nowhere special,
/// `2> /dev/null`, or `2>&1` (following wherever stdout goes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StderrDest {
    #[default]
    Inherit,
    Null,
    Stdout,
}

/// How `command -v NAME` / `type NAME` report what they found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupStyle {
    /// `command -v`: print the path (or bare name for a function or
    /// builtin), nothing when not found.
    CommandV,
    /// `type`: print a `NAME is ...` sentence, nothing when not found.
    Type,
}

/// A vetted operation, compiled by the policy from a statement it
/// allowed (or will allow once the user confirms).
///
/// Not `PartialEq`/`Eq`: `DefineFunction` carries a `brush_parser::ast`
/// node, which only derives those outside of brush-parser's own test
/// build (see its `cfg_attr(any(test, feature = "serde"), ...)`).
/// Nothing here ever compares two `Action`s, so this costs nothing.
#[derive(Debug, Clone)]
pub enum Action {
    /// `true`, `:`, `mkdir -p` on directories that all exist, …
    Noop,
    /// `echo` / `printf`: write `text` exactly as given, to wherever
    /// `dest` says (`>&2` sends it to stderr, `> /dev/null` drops it).
    Print { text: String, dest: StdoutDest },
    /// `mkdir`: every path in `paths` was verified not to exist yet.
    MkDir { paths: Vec<PathBuf>, parents: bool },
    /// `touch`: create each path if absent (recording ownership) or
    /// bump its mtime if present. Vetted by policy.rs's `evaluate_touch`.
    Touch { paths: Vec<PathBuf> },
    /// `rm` restricted to ledger-owned paths.
    Remove {
        paths: Vec<PathBuf>,
        recursive: bool,
        force: bool,
    },
    /// `chmod` restricted to ledger-owned paths.
    Chmod { mode: Mode, paths: Vec<PathBuf> },
    /// `curl` / `wget`: an HTTP(S) GET performed in-process.
    Fetch { url: String, output: FetchOutput },
    /// `echo`/`printf ... >> rcfile`: append text to a recognized shell
    /// rc/profile file (milestone 6's env-file append grammar, vetted by
    /// policy.rs before this action is ever built).
    AppendFile { path: PathBuf, text: String },
    /// `sha256sum FILE...`: print `<hex>  <path>` for each, restricted to
    /// paths this run created.
    Sha256Sum { paths: Vec<PathBuf> },
    /// `sha256sum -c FILE`: verify each `<hex>  <path>` entry (parsed
    /// from a checksums file this run created) against the file on disk.
    Sha256Check { entries: Vec<(String, PathBuf)> },
    /// A command iish has no native implementation for, compiled by
    /// the "subprocess" policy tier (milestone 5, see policy.rs): the
    /// literal, already-parsed argv, exec'd directly — never through a
    /// shell, so no word splitting, globbing, or expansion happens
    /// that the parser didn't already vet. `stdout`/`stderr` carry the
    /// statement's own vetted redirects (`> /dev/null`, `2>&1`, ...).
    Subprocess {
        name: String,
        args: Vec<String>,
        stdout: StdoutDest,
        stderr: StderrDest,
    },
    /// `name() { ... }`: register `name` so a later call to it runs
    /// `body` (a brace-group's statement list) — see policy.rs's
    /// `Verdict::Group`. Defining a function has no effect beyond this;
    /// nothing in `body` runs until the function is called.
    DefineFunction {
        name: String,
        body: ast::CompoundList,
    },
    /// `cp [-r] SRC... DEST`: copy each `(src, dest)` pair natively.
    /// Ledger rules mirror `curl -o`/`wget -O`: a new destination is
    /// always fine, one this run already owns is fine to overwrite, and
    /// a pre-existing foreign destination is governed by
    /// `config.overwrite` (policy.rs's `evaluate_cp`).
    Copy {
        pairs: Vec<(PathBuf, PathBuf)>,
        recursive: bool,
    },
    /// `test`/`[ ]`: a side-effect-free expression, already evaluated to
    /// its truth value by policy.rs at verdict time (the same moment
    /// `mkdir`'s "does this path already exist?" check runs) since
    /// nothing about it needs confirming or deferring.
    Test { result: bool },
    /// `VAR=value [VAR2=value2 ...]`: record each `(name, value)` in the
    /// session's variable table for a later `$VAR` expansion to read
    /// back. No filesystem or process side effects.
    Assign { assignments: Vec<(String, String)> },
    /// `local VAR=value [VAR2 ...]`: declare each name in the innermost
    /// function call's scope (state.rs frames). Errs outside a function.
    DeclareLocal { assignments: Vec<(String, String)> },
    /// `shift [n]`: drop the first `n` positional parameters of the
    /// innermost function call.
    Shift { n: usize },
    /// `unset NAME...` / `unset -f NAME...`: remove variables or
    /// function definitions from the session.
    Unset { names: Vec<String>, functions: bool },
    /// `set -u` / `set +u`: toggle refusing unset-variable expansion.
    SetNounset { on: bool },
    /// `true < /dev/tty` (or `< /dev/null`): succeed exactly when the
    /// device opens for reading — the shell idiom for "is there a
    /// controlling terminal?". Opens and immediately closes; reads
    /// nothing.
    ProbeRead { path: PathBuf },
    /// `cd dir`: change iish's own working directory.
    ChangeDir { path: PathBuf },
    /// `read [-r] NAME < /dev/tty`: read one line from the named device
    /// into a shell variable. Fails (like bash's `read`) when the
    /// device can't be opened or is at EOF.
    ReadLine { name: String, path: PathBuf },
    /// `command -v NAME` / `type NAME`: resolve what NAME would run —
    /// a function defined this run, an iish builtin, or a `$PATH`
    /// binary — printing per `style` and succeeding only if found. Pure
    /// lookup; runs nothing.
    CommandLookup {
        name: String,
        style: LookupStyle,
        dest: StdoutDest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `chmod 755` — the literal bits.
    Octal(u32),
    /// `chmod +x` / `u+x` / `a+x` — OR these bits into the current
    /// mode. (Real chmod filters a bare `+x` through the umask; we
    /// treat it as the given classes, which for installers only ever
    /// means "make this runnable".)
    AddBits(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutput {
    Stdout,
    File(PathBuf),
}

/// Command names iish itself implements (natively or as builtins), for
/// `command -v`/`type` resolution: these would "run" under iish even
/// with no such binary on `$PATH`.
pub const NATIVE_COMMAND_NAMES: &[&str] = &[
    "true",
    ":",
    "echo",
    "printf",
    "mkdir",
    "touch",
    "rm",
    "chmod",
    "cp",
    "curl",
    "wget",
    "sha256sum",
    "set",
    "test",
    "[",
    "local",
    "command",
    "type",
    "unset",
    "shift",
    "return",
    "exit",
    "break",
    "continue",
];

pub fn execute(action: &Action, session: &mut Session, out: &mut Out) -> Result<(), String> {
    match action {
        Action::Noop => Ok(()),
        Action::Print { text, dest } => print_text(text, *dest, out),
        Action::MkDir { paths, parents } => paths
            .iter()
            .try_for_each(|path| mkdir(path, *parents, session)),
        Action::Touch { paths } => paths.iter().try_for_each(|path| touch(path, session)),
        Action::Remove {
            paths,
            recursive,
            force,
        } => paths
            .iter()
            .try_for_each(|path| remove(path, *recursive, *force, session)),
        Action::Chmod { mode, paths } => paths.iter().try_for_each(|path| chmod(path, *mode)),
        Action::Fetch { url, output } => fetch(url, output, session, out),
        Action::AppendFile { path, text } => append_file(path, text, session),
        Action::Sha256Sum { paths } => paths.iter().try_for_each(|path| print_sha256(path, out)),
        Action::Sha256Check { entries } => verify_sha256(entries, out),
        Action::Subprocess {
            name,
            args,
            stdout,
            stderr,
        } => run_subprocess(name, args, *stdout, *stderr, out),
        Action::DefineFunction { name, body } => {
            session.define_function(name.clone(), body.clone());
            Ok(())
        }
        Action::Copy { pairs, recursive } => pairs
            .iter()
            .try_for_each(|(src, dest)| copy_path(src, dest, *recursive, session)),
        // Run as an ordinary statement (not the condition of an
        // `if`/`while`/`until`), a `test`/`[` follows the same
        // errexit-like posture as everything else here: a false result
        // is a failure that aborts the run, not silently ignored.
        Action::Test { result } => {
            if *result {
                Ok(())
            } else {
                Err("test: expression was false".to_string())
            }
        }
        Action::Assign { assignments } => {
            for (name, value) in assignments {
                session.set_variable(name.clone(), value.clone());
            }
            Ok(())
        }
        Action::DeclareLocal { assignments } => {
            for (name, value) in assignments {
                session.declare_local(name.clone(), value.clone())?;
            }
            Ok(())
        }
        Action::Shift { n } => session.shift_positional(*n),
        Action::SetNounset { on } => {
            session.set_nounset(*on);
            Ok(())
        }
        Action::ProbeRead { path } => fs::File::open(path)
            .map(|_| ())
            .map_err(|e| format!("cannot open `{}` for reading: {e}", path.display())),
        Action::ChangeDir { path } => {
            std::env::set_current_dir(path).map_err(|e| format!("cd: `{}`: {e}", path.display()))
        }
        Action::ReadLine { name, path } => {
            if read_line_into(name, path, session)? {
                Ok(())
            } else {
                Err(format!(
                    "read: could not read a line from `{}`",
                    path.display()
                ))
            }
        }
        Action::Unset { names, functions } => {
            for name in names {
                if *functions {
                    session.undefine_function(name);
                } else {
                    session.unset_variable(name);
                }
            }
            Ok(())
        }
        Action::CommandLookup { name, style, dest } => {
            if command_lookup(name, *style, *dest, session, out)? {
                Ok(())
            } else {
                Err(format!("{name}: not found"))
            }
        }
    }
}

/// Like [`execute`], but reports an action's exit status as a `bool`
/// instead of turning "ran fine but said no" into an `Err`. Every action
/// except `Subprocess`, `Test`, and `CommandLookup` either fully
/// succeeds or hits a real, unrecoverable error, so those still
/// propagate as `Err` here too; only a subprocess's exit code, a test
/// expression's result, and a lookup's found/not-found are the kind of
/// "failure" bash's `if`/`while`/`until` conditions are specifically
/// exempted from treating as fatal (see main.rs's `run_if`/`run_condition`).
pub fn execute_returning_status(
    action: &Action,
    session: &mut Session,
    out: &mut Out,
) -> Result<bool, String> {
    match action {
        Action::Test { result } => Ok(*result),
        Action::Subprocess {
            name,
            args,
            stdout,
            stderr,
        } => run_subprocess_status(name, args, *stdout, *stderr, out),
        Action::CommandLookup { name, style, dest } => {
            command_lookup(name, *style, *dest, session, out)
        }
        Action::ProbeRead { path } => Ok(fs::File::open(path).is_ok()),
        Action::ReadLine { name, path } => read_line_into(name, path, session),
        other => execute(other, session, out).map(|()| true),
    }
}

/// Read one line from `path` into the shell variable `name`. `Ok(false)`
/// — bash `read`'s non-zero status — when the device can't be opened or
/// gives EOF before any bytes.
fn read_line_into(name: &str, path: &Path, session: &mut Session) -> Result<bool, String> {
    use std::io::BufRead;
    let Ok(file) = fs::File::open(path) else {
        return Ok(false);
    };
    let mut line = String::new();
    let bytes = std::io::BufReader::new(file)
        .read_line(&mut line)
        .map_err(|e| format!("read: `{}`: {e}", path.display()))?;
    if bytes == 0 {
        return Ok(false);
    }
    if line.ends_with('\n') {
        line.pop();
    }
    session.set_variable(name, line);
    Ok(true)
}

/// Run one already-vetted stage of a multi-stage pipeline: like
/// [`execute_returning_status`], with the previous stage's captured
/// output as this stage's stdin. Only a subprocess actually consumes
/// stdin — no native action reads it — so for everything else the
/// carried bytes are simply dropped, as they would be by a
/// non-stdin-reading program.
pub fn execute_piped(
    action: &Action,
    session: &mut Session,
    stdin: Option<Vec<u8>>,
    out: &mut Out,
) -> Result<bool, String> {
    match action {
        Action::Subprocess {
            name,
            args,
            stdout,
            stderr,
        } => Ok(spawn(name, args, *stdout, *stderr, out, stdin)?.success()),
        other => execute_returning_status(other, session, out),
    }
}

/// Pretend `action` ran, for `--dry-run`: record the paths it would
/// create so later statements (e.g. `rm` of a directory made earlier in
/// the script) are judged against the ledger they would actually see.
pub fn record_would_create(action: &Action, session: &mut Session) {
    match action {
        Action::MkDir { paths, .. } => {
            for path in paths {
                session.record_created(path);
            }
        }
        Action::Touch { paths } => {
            for path in paths {
                if !path.exists() {
                    session.record_created(path);
                }
            }
        }
        Action::Fetch {
            output: FetchOutput::File(path),
            ..
        } => session.record_created(path),
        Action::AppendFile { path, .. } => session.record_created(path),
        Action::DefineFunction { name, body } => {
            session.define_function(name.clone(), body.clone())
        }
        Action::Copy { pairs, .. } => {
            for (_, dest) in pairs {
                session.record_created(dest);
            }
        }
        Action::Assign { assignments } => {
            for (name, value) in assignments {
                session.set_variable(name.clone(), value.clone());
            }
        }
        Action::SetNounset { on } => session.set_nounset(*on),
        _ => {}
    }
}

fn print_text(text: &str, dest: StdoutDest, out: &mut Out) -> Result<(), String> {
    match dest {
        StdoutDest::Null => Ok(()),
        StdoutDest::Stderr => {
            let mut stderr = io::stderr();
            stderr
                .write_all(text.as_bytes())
                .and_then(|()| stderr.flush())
                .map_err(|e| format!("writing to stderr: {e}"))
        }
        StdoutDest::Inherit => out
            .write_all(text.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|e| format!("writing to stdout: {e}")),
    }
}

/// `command -v NAME` / `type NAME`: what would NAME run? A function
/// defined earlier this run wins (as it does in iish's own dispatch),
/// then a native iish command name, then a `$PATH` search for an
/// executable file. Returns whether NAME resolved at all.
fn command_lookup(
    name: &str,
    style: LookupStyle,
    dest: StdoutDest,
    session: &Session,
    out: &mut Out,
) -> Result<bool, String> {
    let found: Option<String> = if session.lookup_function(name).is_some() {
        Some(match style {
            LookupStyle::CommandV => format!("{name}\n"),
            LookupStyle::Type => format!("{name} is a function\n"),
        })
    } else if NATIVE_COMMAND_NAMES.contains(&name) {
        Some(match style {
            LookupStyle::CommandV => format!("{name}\n"),
            LookupStyle::Type => format!("{name} is a shell builtin\n"),
        })
    } else {
        path_search(name).map(|path| match style {
            LookupStyle::CommandV => format!("{}\n", path.display()),
            LookupStyle::Type => format!("{name} is {}\n", path.display()),
        })
    };
    match found {
        Some(text) => {
            print_text(&text, dest, out)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Find `name` as an executable regular file on `$PATH`, like a shell's
/// command lookup would. A name containing `/` is checked as a path
/// directly, no search.
fn path_search(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let is_executable_file = |path: &Path| {
        fs::metadata(path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    if name.contains('/') {
        let path = PathBuf::from(name);
        return is_executable_file(&path).then_some(path);
    }
    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Refuse to operate through a symlink planted between the filesystem
/// root and `path`. `Session::owns` is a lexical prefix match on the
/// path a script *named*; it has no idea that a directory component on
/// the way to the leaf might actually be a symlink — planted by an
/// earlier step, e.g. a `ln -s` the subprocess tier ran — that the OS
/// would silently resolve through to wherever it points. Without this
/// check, `mkdir owned/escape/x` or `rm -rf owned/escape/passwd` with
/// `owned/escape -> /etc` operates on `/etc/x` or `/etc/passwd`, well
/// outside anything this run actually created. Only intermediate
/// components are checked when `allow_symlink_leaf` is set: removing a
/// symlink removes just the link, which is safe; chmod, writes, and
/// reads all follow a symlink leaf to its target, so callers that do
/// those must pass `false`.
fn assert_no_symlink_escape(path: &Path, allow_symlink_leaf: bool) -> Result<(), String> {
    let components: Vec<_> = path.components().collect();
    let Some((leaf, ancestors)) = components.split_last() else {
        return Ok(());
    };
    let mut current = PathBuf::new();
    for component in ancestors {
        current.push(component);
        if is_symlink(&current) {
            return Err(format!(
                "`{}` is a symlink; refusing to operate through it onto `{}`",
                current.display(),
                path.display()
            ));
        }
    }
    if !allow_symlink_leaf {
        current.push(leaf);
        if is_symlink(&current) {
            return Err(format!(
                "`{}` is a symlink; refusing to follow it to its target",
                current.display()
            ));
        }
    }
    Ok(())
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn mkdir(path: &Path, parents: bool, session: &mut Session) -> Result<(), String> {
    if path.exists() {
        if parents {
            return Ok(());
        }
        return Err(format!("mkdir: `{}` already exists", path.display()));
    }
    assert_no_symlink_escape(path, true).map_err(|e| format!("mkdir: {e}"))?;
    // The topmost ancestor that does not exist yet is what this call
    // brings into being; owning it covers the whole subtree beneath.
    let topmost = path
        .ancestors()
        .take_while(|p| !p.exists())
        .last()
        .unwrap_or(path)
        .to_path_buf();
    let result = if parents {
        fs::create_dir_all(path)
    } else {
        fs::create_dir(path)
    };
    result.map_err(|e| format!("mkdir: `{}`: {e}", path.display()))?;
    session.record_created(topmost);
    Ok(())
}

/// `touch`: create `path` empty if it doesn't exist (recording
/// ownership so a later `rm` of it is permitted), or open it to bump its
/// mtime if it does. Refuses to act through a symlink like every other
/// native write.
fn touch(path: &Path, session: &mut Session) -> Result<(), String> {
    assert_no_symlink_escape(path, false).map_err(|e| format!("touch: {e}"))?;
    let existed = path.exists();
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("touch: `{}`: {e}", path.display()))?;
    if !existed {
        session.record_created(path);
    }
    Ok(())
}

fn remove(path: &Path, recursive: bool, force: bool, session: &Session) -> Result<(), String> {
    // The policy already checked ownership; re-check here so no future
    // refactor can reach this code with an unvetted path.
    if !session.owns(path) {
        return Err(format!(
            "rm: `{}` was not created by this run",
            path.display()
        ));
    }
    assert_no_symlink_escape(path, true).map_err(|e| format!("rm: {e}"))?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) if force => return Ok(()),
        Err(e) => return Err(format!("rm: `{}`: {e}", path.display())),
    };
    let result = if metadata.is_dir() {
        if !recursive {
            return Err(format!(
                "rm: `{}` is a directory (missing -r)",
                path.display()
            ));
        }
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|e| format!("rm: `{}`: {e}", path.display()))
}

fn chmod(path: &Path, mode: Mode) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    // Real chmod(2) follows a symlink to its target, so a leaf symlink
    // must be refused too, not just intermediate components.
    assert_no_symlink_escape(path, false).map_err(|e| format!("chmod: {e}"))?;
    let bits = match mode {
        Mode::Octal(bits) => bits,
        Mode::AddBits(add) => {
            let current = fs::metadata(path)
                .map_err(|e| format!("chmod: `{}`: {e}", path.display()))?
                .permissions()
                .mode();
            current | add
        }
    };
    fs::set_permissions(path, fs::Permissions::from_mode(bits))
        .map_err(|e| format!("chmod: `{}`: {e}", path.display()))
}

/// `cp`: copy `src` to `dest`, recursing into a directory only when
/// `recursive` was given (matching real `cp`'s `-r`/`-R` requirement).
/// Only the *destination* is checked for a symlink planted between the
/// filesystem root and the leaf: a destination symlink would let the
/// script write through to a target the overwrite/ownership checks
/// never looked at. The source side follows symlinks like real `cp`
/// does — the policy places no restriction on what a source may name
/// (copying only reads, and the script could name the link's target
/// directly), so refusing them would only break legitimate sources
/// like `/bin/true` on merged-usr systems where `/bin` itself is a
/// symlink to `usr/bin`. Only a new destination enters the ledger;
/// overwriting a pre-existing one leaves it exactly as unowned as it
/// was before (matching `fetch`'s rule).
fn copy_path(
    src: &Path,
    dest: &Path,
    recursive: bool,
    session: &mut Session,
) -> Result<(), String> {
    assert_no_symlink_escape(dest, false).map_err(|e| format!("cp: {e}"))?;
    let existed = dest.exists();
    // Follows a symlink source (leaf or intermediate) to what it
    // actually points at, exactly like `fs::copy`/`read_dir` below will.
    let metadata = fs::metadata(src).map_err(|e| format!("cp: `{}`: {e}", src.display()))?;
    if metadata.is_dir() {
        if !recursive {
            return Err(format!(
                "cp: `{}` is a directory (missing -r)",
                src.display()
            ));
        }
        copy_dir_recursive(src, dest)?;
    } else {
        fs::copy(src, dest)
            .map_err(|e| format!("cp: `{}` -> `{}`: {e}", src.display(), dest.display()))?;
    }
    if !existed {
        session.record_created(dest);
    }
    Ok(())
}

/// Recursive directory copy for `cp -r`: descends `src`, refusing any
/// symlink it finds *inside* the tree — unlike the top-level source
/// path, a nested link was never named by the script (so following it
/// copies something the statement didn't say), and a link cycle would
/// recurse forever.
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| format!("cp: `{}`: {e}", dest.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("cp: `{}`: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("cp: `{}`: {e}", src.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cp: `{}`: {e}", entry.path().display()))?;
        let target = dest.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(format!(
                "cp: `{}` is a symlink; refusing to copy through it",
                entry.path().display()
            ));
        } else if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)
                .map_err(|e| format!("cp: `{}`: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// GET-only fetch, hardened (milestone 6): fixed, generous timeouts so a
/// slow or hanging server can't stall the run forever, a bounded number
/// of redirects, and — when the requested URL is `https://` —
/// `https_only` so a redirect can't silently downgrade the transfer to
/// plaintext `http://`. Installers' own `--connect-timeout`/`--max-time`
/// flags are accepted by the policy layer but not consulted here: iish's
/// client, not the script, decides these.
fn fetch(
    url: &str,
    output: &FetchOutput,
    session: &mut Session,
    out: &mut Out,
) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(true)
        .https_only(url.starts_with("https://"))
        .redirects(5)
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build();
    let response = agent
        .get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut body = response.into_reader();
    match output {
        FetchOutput::Stdout => {
            io::copy(&mut body, out)
                .and_then(|_| out.flush())
                .map_err(|e| format!("GET {url}: writing to stdout: {e}"))?;
        }
        FetchOutput::File(path) => {
            assert_no_symlink_escape(path, false).map_err(|e| format!("GET {url}: {e}"))?;
            let existed = path.exists();
            let mut file = fs::File::create(path)
                .map_err(|e| format!("GET {url}: cannot create `{}`: {e}", path.display()))?;
            io::copy(&mut body, &mut file)
                .map_err(|e| format!("GET {url}: writing `{}`: {e}", path.display()))?;
            // A pre-existing file the user let us overwrite is still
            // theirs, not the script's; only new files enter the ledger.
            if !existed {
                session.record_created(path);
            }
        }
    }
    Ok(())
}

/// Append already-vetted text (the env-file grammar was checked in
/// policy.rs) to `path`, creating it if it doesn't exist yet.
fn append_file(path: &Path, text: &str, session: &mut Session) -> Result<(), String> {
    assert_no_symlink_escape(path, false).map_err(|e| format!("append: {e}"))?;
    let existed = path.exists();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("append: `{}`: {e}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("append: `{}`: {e}", path.display()))?;
    if !existed {
        session.record_created(path);
    }
    Ok(())
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    assert_no_symlink_escape(path, false).map_err(|e| format!("sha256sum: {e}"))?;
    let mut file =
        fs::File::open(path).map_err(|e| format!("sha256sum: `{}`: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|e| format!("sha256sum: `{}`: {e}", path.display()))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn print_sha256(path: &Path, out: &mut Out) -> Result<(), String> {
    let hex = sha256_hex(path)?;
    writeln!(out, "{hex}  {}", path.display())
        .map_err(|e| format!("sha256sum: writing to stdout: {e}"))
}

/// `sha256sum -c`: print `<path>: OK`/`FAILED` per entry, like the real
/// tool, and fail the statement (aborting the run) if anything mismatched.
fn verify_sha256(entries: &[(String, PathBuf)], out: &mut Out) -> Result<(), String> {
    let mut failed = 0usize;
    for (expected, path) in entries {
        let status = match sha256_hex(path) {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => "OK",
            Ok(_) => {
                failed += 1;
                "FAILED"
            }
            Err(_) => {
                failed += 1;
                "FAILED open or read"
            }
        };
        writeln!(out, "{}: {status}", path.display())
            .map_err(|e| format!("sha256sum: writing to stdout: {e}"))?;
    }
    if failed > 0 {
        Err(format!(
            "sha256sum: {failed} computed checksum(s) did NOT match"
        ))
    } else {
        Ok(())
    }
}

/// Exec `name` with `args` directly (no shell in between: `Command`
/// does its own fork/exec, it does not consult `$SHELL`), routing the
/// child's stdout and stderr per the statement's vetted redirects and
/// the caller's capture mode.
fn run_subprocess(
    name: &str,
    args: &[String],
    stdout: StdoutDest,
    stderr: StderrDest,
    out: &mut Out,
) -> Result<(), String> {
    let status = spawn(name, args, stdout, stderr, out, None)?;
    if status.success() {
        Ok(())
    } else {
        let how = status
            .code()
            .map(|code| format!("exit code {code}"))
            .unwrap_or_else(|| "a signal".to_string());
        Err(format!("{name}: failed ({how})"))
    }
}

/// Same fork/exec as [`run_subprocess`], but reports success as a `bool`
/// rather than turning a non-zero exit into an `Err` — a real spawn
/// failure (missing binary, ...) still is one.
fn run_subprocess_status(
    name: &str,
    args: &[String],
    stdout: StdoutDest,
    stderr: StderrDest,
    out: &mut Out,
) -> Result<bool, String> {
    Ok(spawn(name, args, stdout, stderr, out, None)?.success())
}

/// Feed `bytes` to the child's piped stdin from a helper thread, so a
/// child that fills its output pipe before draining its input can't
/// deadlock against us. Write errors (the child closed stdin early —
/// `head`, `grep -q`, ...) are exactly the EPIPE a shell pipeline
/// would shrug off.
fn feed_stdin(handle: Option<std::process::ChildStdin>, bytes: Vec<u8>) {
    if let Some(mut handle) = handle {
        std::thread::spawn(move || {
            let _ = handle.write_all(&bytes);
        });
    }
}

fn spawn(
    name: &str,
    args: &[String],
    stdout: StdoutDest,
    mut stderr: StderrDest,
    out: &mut Out,
    stdin: Option<Vec<u8>>,
) -> Result<std::process::ExitStatus, String> {
    // `2>&1` follows wherever stdout points; resolve the shapes that
    // need no pipe up front.
    if stderr == StderrDest::Stdout && stdout == StdoutDest::Null {
        stderr = StderrDest::Null;
    }
    if stderr == StderrDest::Stdout && stdout == StdoutDest::Inherit && !out.is_capturing() {
        // Approximation: the child's stderr keeps its own inherited
        // stream rather than being dup'd onto iish's stdout — the two
        // only differ if iish's own stdout/stderr point different
        // places, and the child's output still reaches the user.
        stderr = StderrDest::Inherit;
    }

    let mut command = std::process::Command::new(name);
    command.args(args);
    if stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    }

    // Anything that must be rerouted after the fact (captured stdout, a
    // `>&2`, a captured `2>&1`) is piped; `wait_with_output` reads the
    // pipes concurrently, so a chatty child can't deadlock against us.
    let pipe_stdout = matches!(stdout, StdoutDest::Stderr)
        || (stdout == StdoutDest::Inherit && out.is_capturing());
    let pipe_stderr = stderr == StderrDest::Stdout;

    if !pipe_stdout && !pipe_stderr {
        match stdout {
            StdoutDest::Null => {
                command.stdout(std::process::Stdio::null());
            }
            StdoutDest::Inherit | StdoutDest::Stderr => {}
        }
        if stderr == StderrDest::Null {
            command.stderr(std::process::Stdio::null());
        }
        let mut child = command.spawn().map_err(|e| format!("{name}: {e}"))?;
        if let Some(bytes) = stdin {
            feed_stdin(child.stdin.take(), bytes);
        }
        return child.wait().map_err(|e| format!("{name}: {e}"));
    }

    command.stdout(match stdout {
        StdoutDest::Null => std::process::Stdio::null(),
        _ if pipe_stdout => std::process::Stdio::piped(),
        StdoutDest::Inherit | StdoutDest::Stderr => std::process::Stdio::inherit(),
    });
    command.stderr(match stderr {
        StderrDest::Null => std::process::Stdio::null(),
        StderrDest::Inherit => std::process::Stdio::inherit(),
        StderrDest::Stdout => std::process::Stdio::piped(),
    });
    let mut child = command.spawn().map_err(|e| format!("{name}: {e}"))?;
    if let Some(bytes) = stdin {
        feed_stdin(child.stdin.take(), bytes);
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("{name}: {e}"))?;

    let mut route_to_stdout = |bytes: &[u8]| -> Result<(), String> {
        out.write_all(bytes)
            .and_then(|()| out.flush())
            .map_err(|e| format!("{name}: writing output: {e}"))
    };
    if pipe_stdout {
        match stdout {
            StdoutDest::Stderr => {
                io::stderr()
                    .write_all(&output.stdout)
                    .map_err(|e| format!("{name}: writing output: {e}"))?;
            }
            _ => route_to_stdout(&output.stdout)?,
        }
    }
    if pipe_stderr {
        // `2>&1`: the child's stderr joins its stdout's destination.
        route_to_stdout(&output.stderr)?;
    }
    Ok(output.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn run(action: &Action, session: &mut Session) -> Result<(), String> {
        execute(action, session, &mut Out::inherit())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iish-exec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn mkdir_records_topmost_created_dir() {
        let base = scratch("mkdir");
        let deep = base.join("a/b/c");
        let mut session = Session::new();
        run(
            &Action::MkDir {
                paths: vec![deep.clone()],
                parents: true,
            },
            &mut session,
        )
        .unwrap();
        assert!(deep.is_dir());
        // `base` itself was created by the call, so the whole subtree
        // (and `base`'s siblings-to-be) belongs to the run.
        assert!(session.owns(&base));
        assert!(session.owns(&base.join("a/other")));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn remove_refuses_unowned_paths() {
        let base = scratch("rm-foreign");
        fs::create_dir_all(&base).unwrap();
        let mut session = Session::new();
        let err = run(
            &Action::Remove {
                paths: vec![base.clone()],
                recursive: true,
                force: false,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("not created by this run"), "{err}");
        assert!(base.is_dir());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn remove_deletes_owned_paths() {
        let base = scratch("rm-owned");
        let mut session = Session::new();
        run(
            &Action::MkDir {
                paths: vec![base.clone()],
                parents: true,
            },
            &mut session,
        )
        .unwrap();
        run(
            &Action::Remove {
                paths: vec![base.clone()],
                recursive: true,
                force: false,
            },
            &mut session,
        )
        .unwrap();
        assert!(!base.exists());
    }

    #[test]
    fn chmod_sets_and_adds_bits() {
        let base = scratch("chmod");
        fs::create_dir_all(&base).unwrap();
        let file = base.join("tool");
        fs::write(&file, b"#!/bin/true\n").unwrap();
        let mut session = Session::new();
        session.record_created(&base);

        run(
            &Action::Chmod {
                mode: Mode::Octal(0o644),
                paths: vec![file.clone()],
            },
            &mut session,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );

        run(
            &Action::Chmod {
                mode: Mode::AddBits(0o111),
                paths: vec![file.clone()],
            },
            &mut session,
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn subprocess_runs_the_literal_argv() {
        let base = scratch("subprocess");
        let mut session = Session::new();
        run(
            &Action::Subprocess {
                name: "mkdir".to_string(),
                args: vec![base.to_str().unwrap().to_string()],
                stdout: StdoutDest::Inherit,
                stderr: StderrDest::Inherit,
            },
            &mut session,
        )
        .unwrap();
        assert!(base.is_dir());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn subprocess_reports_a_nonzero_exit() {
        let mut session = Session::new();
        let err = run(
            &Action::Subprocess {
                name: "false".to_string(),
                args: vec![],
                stdout: StdoutDest::Inherit,
                stderr: StderrDest::Inherit,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("false"), "{err}");
    }

    #[test]
    fn subprocess_reports_a_missing_binary() {
        let mut session = Session::new();
        let err = run(
            &Action::Subprocess {
                name: "iish-definitely-not-a-real-binary".to_string(),
                args: vec![],
                stdout: StdoutDest::Inherit,
                stderr: StderrDest::Inherit,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("iish-definitely-not-a-real-binary"), "{err}");
    }

    #[test]
    fn subprocess_stdout_is_captured() {
        let mut session = Session::new();
        let mut buf = Vec::new();
        execute(
            &Action::Subprocess {
                name: "echo".to_string(),
                args: vec!["captured".to_string()],
                stdout: StdoutDest::Inherit,
                stderr: StderrDest::Inherit,
            },
            &mut session,
            &mut Out::capture(&mut buf),
        )
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), "captured\n");
    }

    #[test]
    fn print_is_captured_and_null_discards() {
        let mut session = Session::new();
        let mut buf = Vec::new();
        execute(
            &Action::Print {
                text: "hello\n".into(),
                dest: StdoutDest::Inherit,
            },
            &mut session,
            &mut Out::capture(&mut buf),
        )
        .unwrap();
        execute(
            &Action::Print {
                text: "dropped\n".into(),
                dest: StdoutDest::Null,
            },
            &mut session,
            &mut Out::capture(&mut buf),
        )
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&buf), "hello\n");
    }

    #[test]
    fn command_lookup_finds_functions_builtins_and_binaries() {
        let mut session = Session::new();
        let program = crate::parser::parse("f() { true; }").unwrap();
        let crate::parser::ast::Command::Function(def) =
            &program.complete_commands[0].0[0].0.first.seq[0]
        else {
            panic!("expected function definition");
        };
        let crate::parser::ast::FunctionBody(
            crate::parser::ast::CompoundCommand::BraceGroup(group),
            _,
        ) = &def.body
        else {
            panic!("expected brace group body");
        };
        session.define_function("myfunc", group.list.clone());

        let mut buf = Vec::new();
        assert!(command_lookup(
            "myfunc",
            LookupStyle::CommandV,
            StdoutDest::Inherit,
            &session,
            &mut Out::capture(&mut buf)
        )
        .unwrap());
        assert_eq!(String::from_utf8_lossy(&buf), "myfunc\n");

        let mut buf = Vec::new();
        assert!(command_lookup(
            "echo",
            LookupStyle::Type,
            StdoutDest::Inherit,
            &session,
            &mut Out::capture(&mut buf)
        )
        .unwrap());
        assert!(String::from_utf8_lossy(&buf).contains("shell builtin"));

        // `sh` exists on every test system.
        let mut buf = Vec::new();
        assert!(command_lookup(
            "sh",
            LookupStyle::CommandV,
            StdoutDest::Inherit,
            &session,
            &mut Out::capture(&mut buf)
        )
        .unwrap());
        assert!(String::from_utf8_lossy(&buf).contains("/sh"));

        assert!(!command_lookup(
            "iish-definitely-not-a-real-binary",
            LookupStyle::CommandV,
            StdoutDest::Inherit,
            &session,
            &mut Out::inherit()
        )
        .unwrap());
    }

    // A subprocess (e.g. `ln -s`) can plant a symlink under a directory
    // this run owns. Session::owns() is a lexical prefix match with no
    // idea that a path component might actually redirect elsewhere on
    // disk; these reproduce that escape and confirm assert_no_symlink_escape
    // now blocks it before any of these ever call the real syscall.

    #[test]
    fn mkdir_refuses_to_create_through_a_symlink() {
        let base = scratch("mkdir-symlink");
        let outside = scratch("mkdir-symlink-outside");
        fs::create_dir_all(&base).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        let mut session = Session::new();
        session.record_created(&base);

        let err = run(
            &Action::MkDir {
                paths: vec![base.join("escape").join("newdir")],
                parents: true,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            !outside.exists(),
            "must not have been created via the symlink"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn remove_refuses_to_delete_through_a_symlink() {
        let base = scratch("rm-symlink");
        let outside = scratch("rm-symlink-outside");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim.txt");
        fs::write(&victim, b"do not delete me").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        let mut session = Session::new();
        session.record_created(&base);

        let err = run(
            &Action::Remove {
                paths: vec![base.join("escape").join("victim.txt")],
                recursive: false,
                force: false,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            victim.exists(),
            "the file outside the owned tree must survive"
        );
        fs::remove_dir_all(&base).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn chmod_refuses_a_symlink_leaf() {
        let base = scratch("chmod-symlink-leaf");
        fs::create_dir_all(&base).unwrap();
        let target = base.join("target.txt");
        fs::write(&target, b"x").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut session = Session::new();

        let err = run(
            &Action::Chmod {
                mode: Mode::Octal(0o777),
                paths: vec![link],
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644,
            "chmod must not have followed the symlink to its target"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn chmod_refuses_through_an_intermediate_symlink() {
        let base = scratch("chmod-symlink-intermediate");
        let outside = scratch("chmod-symlink-intermediate-outside");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let target = outside.join("target.txt");
        fs::write(&target, b"x").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        let mut session = Session::new();

        let err = run(
            &Action::Chmod {
                mode: Mode::Octal(0o777),
                paths: vec![base.join("escape").join("target.txt")],
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_dir_all(&base).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    // `cp`'s source side is unrestricted by policy (it only reads), so
    // unlike every mutating action it must tolerate symlinks on the way
    // to the source — most importantly `/bin -> usr/bin` on merged-usr
    // systems, where `cp /bin/true ...` is a completely ordinary
    // installer operation. The destination stays strict.

    #[test]
    fn copy_follows_a_symlinked_source_directory() {
        let base = scratch("cp-src-intermediate-symlink");
        fs::create_dir_all(base.join("usr/bin")).unwrap();
        fs::write(base.join("usr/bin/tool"), b"tool bytes").unwrap();
        // The merged-usr shape: bin -> usr/bin.
        std::os::unix::fs::symlink("usr/bin", base.join("bin")).unwrap();
        let dest = base.join("copied-tool");
        let mut session = Session::new();

        run(
            &Action::Copy {
                pairs: vec![(base.join("bin/tool"), dest.clone())],
                recursive: false,
            },
            &mut session,
        )
        .unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"tool bytes");
        assert!(session.owns(&dest), "a new destination enters the ledger");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn copy_follows_a_symlink_leaf_source() {
        let base = scratch("cp-src-leaf-symlink");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("real"), b"real bytes").unwrap();
        std::os::unix::fs::symlink("real", base.join("link")).unwrap();
        let dest = base.join("copied");
        let mut session = Session::new();

        run(
            &Action::Copy {
                pairs: vec![(base.join("link"), dest.clone())],
                recursive: false,
            },
            &mut session,
        )
        .unwrap();
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"real bytes",
            "cp follows a symlink source to its content, like real cp"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn copy_refuses_a_symlinked_destination() {
        let base = scratch("cp-dest-symlink");
        let outside = scratch("cp-dest-symlink-outside");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(base.join("src"), b"payload").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("escape")).unwrap();
        let mut session = Session::new();

        let err = run(
            &Action::Copy {
                pairs: vec![(base.join("src"), base.join("escape").join("victim"))],
                recursive: false,
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            !outside.join("victim").exists(),
            "nothing may be written through the destination symlink"
        );
        fs::remove_dir_all(&base).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[test]
    fn sha256sum_refuses_a_symlink_leaf() {
        let base = scratch("sha256-symlink-leaf");
        fs::create_dir_all(&base).unwrap();
        let secret = base.join("secret.txt");
        fs::write(&secret, b"outside content, not this run's to read").unwrap();
        let link = base.join("owned-name.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let mut session = Session::new();
        session.record_created(&link);

        let err = run(&Action::Sha256Sum { paths: vec![link] }, &mut session).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        fs::remove_dir_all(&base).unwrap();
    }
}
