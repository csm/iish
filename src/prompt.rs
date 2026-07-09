//! Confirmation prompts for `ask` verdicts.
//!
//! The script itself occupies stdin (`curl … | iish`), so questions go
//! to the controlling terminal, `/dev/tty` (see PLAN.md). `--yes` and
//! `--no` resolve every ask non-interactively for scripted use.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskMode {
    /// Ask on /dev/tty (the default).
    Tty,
    /// `--yes`: confirm everything.
    AssumeYes,
    /// `--no`: refuse everything that would ask.
    AssumeNo,
}

/// Resolve one confirmation. `raw` is the statement as written, and
/// `reason` is the policy's explanation of what needs confirming.
pub fn confirm(mode: AskMode, raw: &str, reason: &str) -> Result<bool, String> {
    match mode {
        AskMode::AssumeYes => {
            eprintln!("iish: --yes: proceeding with `{raw}` ({reason})");
            Ok(true)
        }
        AskMode::AssumeNo => Ok(false),
        AskMode::Tty => ask_tty(raw, reason),
    }
}

fn ask_tty(raw: &str, reason: &str) -> Result<bool, String> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("cannot open /dev/tty to ask ({e}); rerun with --yes or --no"))?;
    let mut tty = BufReader::new(tty);
    write!(
        tty.get_mut(),
        "iish: {raw}\n      {reason}\n      proceed? [y/N] "
    )
    .and_then(|()| tty.get_mut().flush())
    .map_err(|e| format!("cannot write to /dev/tty: {e}"))?;
    let mut answer = String::new();
    tty.read_line(&mut answer)
        .map_err(|e| format!("cannot read from /dev/tty: {e}"))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}
