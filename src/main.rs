//! iish — a safe interpreter for `curl … | sh` install scripts.
//!
//! Reads a bash script from a file argument or stdin, parses it, and
//! evaluates every statement against an installer safety policy.
//! Currently runs in plan/report mode: it shows what it would allow,
//! prompt for, or refuse. Native execution is milestone 2 (see PLAN.md).

mod exec;
mod parser;
mod policy;
mod state;

use policy::Verdict;
use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "usage: iish [script.sh]        (reads stdin if no file given)
       curl -fsSL https://example.com/install.sh | iish";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let script = match args.as_slice() {
        [] => {
            let mut buf = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
                eprintln!("iish: failed to read stdin: {e}");
                return ExitCode::FAILURE;
            }
            buf
        }
        [path] if path != "-h" && path != "--help" => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("iish: cannot read `{path}`: {e}");
                return ExitCode::FAILURE;
            }
        },
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    let nodes = parser::parse(&script);
    if nodes.is_empty() {
        eprintln!("iish: script contains no commands");
        return ExitCode::FAILURE;
    }

    let session = state::Session::new();
    let mut denied = 0usize;

    println!("iish plan ({} statements):", nodes.len());
    for node in &nodes {
        let raw = match node {
            parser::Node::Simple(cmd) => &cmd.raw,
            parser::Node::Unsupported { raw, .. } => raw,
        };
        let (tag, detail) = match policy::evaluate(node, &session) {
            Verdict::Allow(why) => ("ALLOW ", why),
            Verdict::Prompt(why) => ("PROMPT", why),
            Verdict::Deny(why) => {
                denied += 1;
                ("DENY  ", why)
            }
        };
        println!("  [{tag}] {raw}");
        println!("           {detail}");
    }

    if denied > 0 {
        println!("\n{denied} statement(s) would be refused; nothing was executed.");
        ExitCode::FAILURE
    } else {
        println!("\nAll statements pass policy; execution is not implemented yet.");
        ExitCode::SUCCESS
    }
}
