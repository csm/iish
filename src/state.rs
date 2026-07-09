//! Session ledger: what this script run has created so far, the
//! functions it has defined, its variables (global and function-local),
//! and the call-frame stack behind positional parameters and `local`.
//!
//! The ledger is the source of truth for "the script owns this path".
//! Deletion and mode changes are only permitted on owned paths.

use crate::parser::ast;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

/// One function call in progress: the arguments the call was made with
/// (its `$1`/`$@`/`$#`) and the variables `local` has declared in it so
/// far. Frames stack — bash scopes `local` dynamically, so a callee
/// sees (and may assign) its caller's locals too.
#[derive(Debug)]
struct Frame {
    function_name: String,
    positional: Vec<String>,
    locals: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct Session {
    /// Paths (files and directories) created by this run.
    created: HashSet<PathBuf>,
    /// Functions defined by this run so far, by name, keyed to the
    /// brace-group body that a call should run (see policy.rs's
    /// `Verdict::Group`).
    functions: HashMap<String, ast::CompoundList>,
    /// Global shell variables assigned by a `VAR=value` statement so
    /// far this run (parser.rs reads these back for a later
    /// `$VAR`/`${VAR}` expansion, falling back to the real process
    /// environment only when a name was never assigned here).
    variables: HashMap<String, String>,
    /// Function calls in progress, innermost last.
    frames: Vec<Frame>,
    /// The exit status of the last statement that ran, for `$?`.
    last_status: i32,
    /// Whether expanding an unset variable is refused (`set -u`),
    /// matching bash: off by default (unset expands to empty — real
    /// installers probe optional environment variables constantly, and
    /// were all written against that default), on once the script says
    /// `set -u`, off again on `set +u` (rustup toggles it around its
    /// env-var dispatcher). Empty expansions feeding a dangerous
    /// operation are caught where the danger is: every action is still
    /// vetted by the policy/ledger, so `rm -rf "/$TYPO"` is refused as
    /// `rm -rf /` regardless.
    nounset: bool,
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

    /// `unset -f name`: drop a function definition. Unsetting a name
    /// that was never defined is fine (matching bash).
    pub fn undefine_function(&mut self, name: &str) {
        self.functions.remove(name);
    }

    /// The body to run for a call to `name`, if it was defined earlier
    /// in this run.
    pub fn lookup_function(&self, name: &str) -> Option<&ast::CompoundList> {
        self.functions.get(name)
    }

    /// Record a `VAR=value` assignment. If any enclosing function call
    /// declared `name` with `local`, the innermost such declaration is
    /// what's assigned (bash's dynamic scoping); otherwise the global
    /// table is, overwriting any earlier value.
    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        for frame in self.frames.iter_mut().rev() {
            if let Some(slot) = frame.locals.get_mut(&name) {
                *slot = value.into();
                return;
            }
        }
        self.variables.insert(name, value.into());
    }

    /// `unset VAR`: remove every binding of `name` — local declarations
    /// in any live frame and the global — so a later expansion sees it
    /// as unset. Unsetting a name that was never set is fine.
    pub fn unset_variable(&mut self, name: &str) {
        for frame in &mut self.frames {
            frame.locals.remove(name);
        }
        self.variables.remove(name);
    }

    /// The value of `name` as this run sees it: the innermost `local`
    /// declaration first (bash's dynamic scoping), then the global
    /// table. The process-environment fallback for names never assigned
    /// in the script lives one level up, in parser.rs.
    pub fn get_variable(&self, name: &str) -> Option<&str> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.locals.get(name) {
                return Some(value);
            }
        }
        self.variables.get(name).map(String::as_str)
    }

    /// `local NAME=value` (or `local NAME`, with an empty value):
    /// declare `name` in the innermost function call's scope. Errors
    /// outside any function call, matching bash.
    pub fn declare_local(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), String> {
        match self.frames.last_mut() {
            Some(frame) => {
                frame.locals.insert(name.into(), value.into());
                Ok(())
            }
            None => Err("`local` can only be used inside a function".to_string()),
        }
    }

    /// Enter a function call: `args` become the body's `$1`/`$@`/`$#`,
    /// and `local` declarations land in this frame until [`Self::pop_frame`].
    pub fn push_frame(&mut self, function_name: impl Into<String>, args: Vec<String>) {
        self.frames.push(Frame {
            function_name: function_name.into(),
            positional: args,
            locals: HashMap::new(),
        });
    }

    /// Leave the innermost function call, dropping its locals and
    /// positional parameters.
    pub fn pop_frame(&mut self) {
        self.frames.pop();
    }

    /// True if a function call is in progress (so `local` and `return`
    /// are meaningful).
    pub fn in_function(&self) -> bool {
        !self.frames.is_empty()
    }

    /// The positional parameters (`$1`, `$2`, ...) in effect right now:
    /// the innermost function call's arguments, or — outside any call —
    /// the script's own, which iish never populates (it takes no script
    /// arguments of its own), so an empty list.
    pub fn positional(&self) -> &[String] {
        self.frames
            .last()
            .map(|f| f.positional.as_slice())
            .unwrap_or(&[])
    }

    /// `shift [n]`: drop the first `n` positional parameters of the
    /// innermost frame. Errs when `n` exceeds `$#`, matching bash's
    /// non-zero status (which aborts under iish's fail-fast posture
    /// unless checked).
    pub fn shift_positional(&mut self, n: usize) -> Result<(), String> {
        let Some(frame) = self.frames.last_mut() else {
            return Err(
                "`shift` outside a function has nothing to shift: iish passes no \
                        arguments to the script itself"
                    .to_string(),
            );
        };
        if n > frame.positional.len() {
            return Err(format!(
                "shift: {n} exceeds the {} positional parameter(s) of `{}`",
                frame.positional.len(),
                frame.function_name
            ));
        }
        frame.positional.drain(..n);
        Ok(())
    }

    /// What `$0` expands to. iish always runs a script, never an
    /// interactive shell; inside a function bash keeps `$0` as the
    /// script name too, so no frame lookup here.
    pub fn script_name(&self) -> &str {
        "iish"
    }

    /// The exit status of the last statement that completed, for `$?`.
    pub fn last_status(&self) -> i32 {
        self.last_status
    }

    pub fn set_last_status(&mut self, status: i32) {
        self.last_status = status;
    }

    /// Whether an unset variable expansion is refused (`set -u` seen).
    pub fn nounset(&self) -> bool {
        self.nounset
    }

    pub fn set_nounset(&mut self, on: bool) {
        self.nounset = on;
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

    #[test]
    fn local_declarations_scope_to_their_frame() {
        let mut s = Session::new();
        s.set_variable("X", "global");
        s.push_frame("f", vec![]);
        s.declare_local("X", "inner").unwrap();
        assert_eq!(s.get_variable("X"), Some("inner"));
        // Dynamic scoping: assignment inside the frame hits the local.
        s.set_variable("X", "changed");
        assert_eq!(s.get_variable("X"), Some("changed"));
        s.pop_frame();
        assert_eq!(s.get_variable("X"), Some("global"));
    }

    #[test]
    fn callee_sees_and_assigns_callers_local() {
        let mut s = Session::new();
        s.push_frame("outer", vec![]);
        s.declare_local("X", "outer-value").unwrap();
        s.push_frame("inner", vec![]);
        assert_eq!(s.get_variable("X"), Some("outer-value"));
        s.set_variable("X", "set-by-inner");
        s.pop_frame();
        assert_eq!(s.get_variable("X"), Some("set-by-inner"));
        s.pop_frame();
        assert_eq!(s.get_variable("X"), None);
    }

    #[test]
    fn local_outside_a_function_is_an_error() {
        let mut s = Session::new();
        assert!(s.declare_local("X", "v").is_err());
    }

    #[test]
    fn positional_parameters_follow_the_innermost_frame() {
        let mut s = Session::new();
        assert!(s.positional().is_empty());
        s.push_frame("f", vec!["a".into(), "b".into()]);
        assert_eq!(s.positional(), ["a", "b"]);
        s.shift_positional(1).unwrap();
        assert_eq!(s.positional(), ["b"]);
        assert!(s.shift_positional(2).is_err());
        s.pop_frame();
        assert!(s.positional().is_empty());
    }
}
