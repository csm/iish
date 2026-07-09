//! Native execution of allowed operations (milestone 4).
//!
//! Nothing here shells out. The policy compiles each statement it
//! passes into an [`Action`]; this module gives every action a Rust
//! implementation that consults and updates the [`Session`] ledger:
//! directory and file creation records ownership, deletion re-checks
//! it, and fetches are performed by iish's own GET-only HTTP client
//! rather than a real curl/wget binary. Executing an action never
//! re-interprets shell syntax.

use crate::parser::ast;
use crate::state::Session;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// `echo` / `printf`: write `text` to stdout exactly as given.
    Print { text: String },
    /// `mkdir`: every path in `paths` was verified not to exist yet.
    MkDir { paths: Vec<PathBuf>, parents: bool },
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
    /// that the parser didn't already vet.
    Subprocess { name: String, args: Vec<String> },
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

pub fn execute(action: &Action, session: &mut Session) -> Result<(), String> {
    match action {
        Action::Noop => Ok(()),
        Action::Print { text } => {
            let mut stdout = io::stdout();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("writing to stdout: {e}"))
        }
        Action::MkDir { paths, parents } => paths
            .iter()
            .try_for_each(|path| mkdir(path, *parents, session)),
        Action::Remove {
            paths,
            recursive,
            force,
        } => paths
            .iter()
            .try_for_each(|path| remove(path, *recursive, *force, session)),
        Action::Chmod { mode, paths } => paths.iter().try_for_each(|path| chmod(path, *mode)),
        Action::Fetch { url, output } => fetch(url, output, session),
        Action::AppendFile { path, text } => append_file(path, text, session),
        Action::Sha256Sum { paths } => paths.iter().try_for_each(|path| print_sha256(path)),
        Action::Sha256Check { entries } => verify_sha256(entries),
        Action::Subprocess { name, args } => run_subprocess(name, args),
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
    }
}

/// Like [`execute`], but reports an action's exit status as a `bool`
/// instead of turning "ran fine but said no" into an `Err`. Every action
/// except `Subprocess` and `Test` either fully succeeds or hits a real,
/// unrecoverable error, so those still propagate as `Err` here too; only
/// a subprocess's exit code and a test expression's result are the kind
/// of "failure" bash's `if`/`while`/`until` conditions are specifically
/// exempted from treating as fatal (see main.rs's `run_if`/`run_condition`).
pub fn execute_returning_status(action: &Action, session: &mut Session) -> Result<bool, String> {
    match action {
        Action::Test { result } => Ok(*result),
        Action::Subprocess { name, args } => run_subprocess_status(name, args),
        other => execute(other, session).map(|()| true),
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
        _ => {}
    }
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
/// Both ends are checked for a symlink planted between the filesystem
/// root and the leaf, same as every other native filesystem action
/// here — a source symlink would let the script read a file it was
/// never granted access to, and a destination symlink would let it
/// write through to an arbitrary target. Only a new destination enters
/// the ledger; overwriting a pre-existing one leaves it exactly as
/// unowned as it was before (matching `fetch`'s rule).
fn copy_path(
    src: &Path,
    dest: &Path,
    recursive: bool,
    session: &mut Session,
) -> Result<(), String> {
    assert_no_symlink_escape(src, false).map_err(|e| format!("cp: {e}"))?;
    assert_no_symlink_escape(dest, false).map_err(|e| format!("cp: {e}"))?;
    let existed = dest.exists();
    let metadata =
        fs::symlink_metadata(src).map_err(|e| format!("cp: `{}`: {e}", src.display()))?;
    if metadata.is_dir() {
        if !recursive {
            return Err(format!(
                "cp: `{}` is a directory (missing -r)",
                src.display()
            ));
        }
        copy_dir_recursive(src, dest)?;
    } else if metadata.file_type().is_symlink() {
        return Err(format!(
            "cp: `{}` is a symlink; refusing to copy through it",
            src.display()
        ));
    } else {
        fs::copy(src, dest)
            .map_err(|e| format!("cp: `{}` -> `{}`: {e}", src.display(), dest.display()))?;
    }
    if !existed {
        session.record_created(dest);
    }
    Ok(())
}

/// Recursive directory copy for `cp -r`: descends `src`, refusing to
/// follow any symlink it finds along the way rather than silently
/// copying whatever it points at.
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
fn fetch(url: &str, output: &FetchOutput, session: &mut Session) -> Result<(), String> {
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
            let mut stdout = io::stdout();
            io::copy(&mut body, &mut stdout)
                .and_then(|_| stdout.flush())
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

fn print_sha256(path: &Path) -> Result<(), String> {
    let hex = sha256_hex(path)?;
    writeln!(io::stdout(), "{hex}  {}", path.display())
        .map_err(|e| format!("sha256sum: writing to stdout: {e}"))
}

/// `sha256sum -c`: print `<path>: OK`/`FAILED` per entry, like the real
/// tool, and fail the statement (aborting the run) if anything mismatched.
fn verify_sha256(entries: &[(String, PathBuf)]) -> Result<(), String> {
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
        writeln!(io::stdout(), "{}: {status}", path.display())
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
/// does its own fork/exec, it does not consult `$SHELL`), inheriting
/// this process's stdio so the child can prompt or stream output.
fn run_subprocess(name: &str, args: &[String]) -> Result<(), String> {
    let status = spawn(name, args)?;
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
fn run_subprocess_status(name: &str, args: &[String]) -> Result<bool, String> {
    Ok(spawn(name, args)?.success())
}

fn spawn(name: &str, args: &[String]) -> Result<std::process::ExitStatus, String> {
    std::process::Command::new(name)
        .args(args)
        .status()
        .map_err(|e| format!("{name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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
        execute(
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
        let err = execute(
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
        execute(
            &Action::MkDir {
                paths: vec![base.clone()],
                parents: true,
            },
            &mut session,
        )
        .unwrap();
        execute(
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

        execute(
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

        execute(
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
        execute(
            &Action::Subprocess {
                name: "mkdir".to_string(),
                args: vec![base.to_str().unwrap().to_string()],
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
        let err = execute(
            &Action::Subprocess {
                name: "false".to_string(),
                args: vec![],
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("false"), "{err}");
    }

    #[test]
    fn subprocess_reports_a_missing_binary() {
        let mut session = Session::new();
        let err = execute(
            &Action::Subprocess {
                name: "iish-definitely-not-a-real-binary".to_string(),
                args: vec![],
            },
            &mut session,
        )
        .unwrap_err();
        assert!(err.contains("iish-definitely-not-a-real-binary"), "{err}");
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

        let err = execute(
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

        let err = execute(
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

        let err = execute(
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

        let err = execute(
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

        let err = execute(&Action::Sha256Sum { paths: vec![link] }, &mut session).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        fs::remove_dir_all(&base).unwrap();
    }
}
