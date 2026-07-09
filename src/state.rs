//! Session ledger: what this script run has created so far, and the
//! functions it has defined.
//!
//! The ledger is the source of truth for "the script owns this path".
//! Deletion and mode changes are only permitted on owned paths.

use crate::parser::ast;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default)]
pub struct Session {
    /// Paths (files and directories) created by this run.
    created: HashSet<PathBuf>,
    /// Functions defined by this run so far, by name, keyed to the
    /// brace-group body that a call should run (see policy.rs's
    /// `Verdict::Group`).
    functions: HashMap<String, ast::CompoundList>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the script created `path`. Recording a directory
    /// covers everything beneath it.
    pub fn record_created(&mut self, path: impl AsRef<Path>) {
        self.created.insert(normalize(path.as_ref()));
    }

    /// True if `path` (or an ancestor directory of it) was created by
    /// this run — i.e. the script may delete or modify it freely.
    pub fn owns(&self, path: &Path) -> bool {
        normalize(path)
            .ancestors()
            .any(|p| self.created.contains(p))
    }

    /// Record a function definition (`name() { ... }`), overwriting any
    /// earlier definition of the same name — matching bash, where a
    /// later definition replaces an earlier one.
    pub fn define_function(&mut self, name: impl Into<String>, body: ast::CompoundList) {
        self.functions.insert(name.into(), body);
    }

    /// The body to run for a call to `name`, if it was defined earlier
    /// in this run.
    pub fn lookup_function(&self, name: &str) -> Option<&ast::CompoundList> {
        self.functions.get(name)
    }
}

/// Make `path` absolute (against the current directory) and resolve `.`
/// and `..` lexically, so ledger entries and lookups compare like with
/// like regardless of how the script spelled the path. Symlinks are not
/// resolved: the ledger tracks the names the script used, not the
/// inodes behind them.
pub fn normalize(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owns_created_paths_and_children() {
        let mut s = Session::new();
        s.record_created("/opt/tool");
        assert!(s.owns(Path::new("/opt/tool")));
        assert!(s.owns(Path::new("/opt/tool/bin/x")));
        assert!(!s.owns(Path::new("/opt/other")));
        assert!(!s.owns(Path::new("/opt")));
    }

    #[test]
    fn ownership_survives_dot_and_dotdot_spellings() {
        let mut s = Session::new();
        s.record_created("/opt/tool");
        assert!(s.owns(Path::new("/opt/./tool")));
        assert!(s.owns(Path::new("/opt/other/../tool/bin")));
        assert!(!s.owns(Path::new("/opt/tool/../other")));
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let mut s = Session::new();
        let cwd = std::env::current_dir().unwrap();
        s.record_created(cwd.join("staging"));
        assert!(s.owns(Path::new("staging/sub/file")));
        assert!(!s.owns(Path::new("elsewhere")));
    }
}
