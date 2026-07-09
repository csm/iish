//! Native execution of allowed operations (milestone 4).
//!
//! Nothing here shells out. Each allowed operation gets a Rust
//! implementation that consults and updates the [`Session`] ledger:
//! file/dir creation records ownership, deletion re-checks it, fetches
//! go through iish's own GET-only HTTP client, and env-file appends are
//! validated against a restricted grammar before being written.

use crate::parser::ast::SimpleCommand;
use crate::state::Session;

/// Execute a command the policy allowed. Placeholder until milestone 4;
/// today `main` runs in plan/report mode only.
#[allow(dead_code)]
pub fn execute(cmd: &SimpleCommand, _session: &mut Session) -> std::io::Result<()> {
    Err(std::io::Error::other(format!(
        "execution not implemented yet (would run: {cmd})"
    )))
}
