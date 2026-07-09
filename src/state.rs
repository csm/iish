//! Session ledger: what this script run has created so far.
//!
//! The ledger is the source of truth for "the script owns this path".
//! Deletion and mode changes are only permitted on owned paths.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default)]
pub struct Session {
    /// Paths (files and directories) created by this run.
    created: HashSet<PathBuf>,
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
