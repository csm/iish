//! Session ledger: what this script run has created so far.
//!
//! The ledger is the source of truth for "the script owns this path".
//! Deletion and mode changes are only permitted on owned paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Session {
    /// Paths (files and directories) created by this run.
    created: HashSet<PathBuf>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the script created `path`. Unused until execution
    /// lands in milestone 2 (tests exercise it meanwhile).
    #[allow(dead_code)]
    pub fn record_created(&mut self, path: impl Into<PathBuf>) {
        self.created.insert(path.into());
    }

    /// True if `path` (or an ancestor directory of it) was created by
    /// this run — i.e. the script may delete or modify it freely.
    pub fn owns(&self, path: &Path) -> bool {
        path.ancestors().any(|p| self.created.contains(p))
    }
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
}
