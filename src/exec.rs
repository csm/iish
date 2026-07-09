//! Native execution of allowed operations (milestone 4).
//!
//! Nothing here shells out. The policy compiles each statement it
//! passes into an [`Action`]; this module gives every action a Rust
//! implementation that consults and updates the [`Session`] ledger:
//! directory and file creation records ownership, deletion re-checks
//! it, and fetches are performed by iish's own GET-only HTTP client
//! rather than a real curl/wget binary. Executing an action never
//! re-interprets shell syntax.

use crate::state::Session;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// A vetted operation, compiled by the policy from a statement it
/// allowed (or will allow once the user confirms).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// A command iish has no native implementation for, compiled by
    /// the "subprocess" policy tier (milestone 5, see policy.rs): the
    /// literal, already-parsed argv, exec'd directly — never through a
    /// shell, so no word splitting, globbing, or expansion happens
    /// that the parser didn't already vet.
    Subprocess { name: String, args: Vec<String> },
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
        Action::Subprocess { name, args } => run_subprocess(name, args),
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
        _ => {}
    }
}

fn mkdir(path: &Path, parents: bool, session: &mut Session) -> Result<(), String> {
    if path.exists() {
        if parents {
            return Ok(());
        }
        return Err(format!("mkdir: `{}` already exists", path.display()));
    }
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

fn fetch(url: &str, output: &FetchOutput, session: &mut Session) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new().try_proxy_from_env(true).build();
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

/// Exec `name` with `args` directly (no shell in between: `Command`
/// does its own fork/exec, it does not consult `$SHELL`), inheriting
/// this process's stdio so the child can prompt or stream output.
fn run_subprocess(name: &str, args: &[String]) -> Result<(), String> {
    let status = std::process::Command::new(name)
        .args(args)
        .status()
        .map_err(|e| format!("{name}: {e}"))?;
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
}
