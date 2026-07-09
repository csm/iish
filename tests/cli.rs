//! End-to-end tests: run the real `iish` binary on small scripts and
//! observe what it executes (and refuses to execute) on disk.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Run iish with `args`, feeding `script` on stdin. Always passes
/// `--no-config` so tests are hermetic regardless of whatever real
/// config file the host running them happens to have; tests that
/// exercise config-file loading itself use `iish_raw`.
fn iish(script: &str, args: &[&str]) -> Output {
    let mut all_args = vec!["--no-config"];
    all_args.extend_from_slice(args);
    iish_raw(script, &all_args)
}

/// Like `iish`, but without forcing `--no-config` — for tests that
/// exercise config-file loading.
fn iish_raw(script: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_iish"));
    // Tests fetch from 127.0.0.1; don't let an ambient proxy intercept.
    for var in ["http_proxy", "https_proxy", "all_proxy"] {
        command.env_remove(var).env_remove(var.to_uppercase());
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("iish should spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A fresh scratch path (not created) unique to this test and process.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("iish-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Serve `body` over HTTP for `hits` GET requests on an ephemeral local
/// port, returning the URL to fetch.
fn serve(body: &'static [u8], hits: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(hits) {
            let mut stream = stream.unwrap();
            // Read until the end of the request headers.
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() == 1 {
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET "), "expected a GET request");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    format!("http://{addr}/payload.bin")
}

#[test]
fn echo_prints_to_stdout() {
    let out = iish("echo hello world\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "hello world\n");
}

#[test]
fn mkdir_then_rm_of_created_dir_roundtrips() {
    let base = scratch("roundtrip");
    let script = format!("mkdir -p {0}/pkg/bin\nrm -r {0}\n", base.display());
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!base.exists(), "rm of a created dir should have run");
}

#[test]
fn rm_of_preexisting_dir_is_refused() {
    let base = scratch("foreign");
    fs::create_dir_all(&base).unwrap();
    let out = iish(&format!("rm -rf {}\n", base.display()), &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("refusing"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(base.is_dir(), "pre-existing dir must survive");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn deny_aborts_before_later_statements() {
    let base = scratch("abort");
    let script = format!("sudo make install\nmkdir {}\n", base.display());
    let out = iish(&script, &["--deny", "sudo"]);
    assert!(!out.status.success());
    assert!(
        !base.exists(),
        "statements after a refusal must not execute"
    );
}

#[test]
fn unknown_command_prompts_and_runs_as_a_subprocess_when_allowed() {
    let base = scratch("subprocess");
    let out = iish(
        &format!("mkdir-and-touch {}\n", base.display()),
        &["--allow", "mkdir-and-touch"],
    );
    // No such binary exists, so the subprocess itself fails, but the
    // point is that it was actually attempted (not silently denied).
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("mkdir-and-touch"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn subprocess_tier_runs_a_real_binary_when_allowed() {
    let base = scratch("cp-subprocess");
    fs::create_dir_all(&base).unwrap();
    let src = base.join("src.txt");
    let dst = base.join("dst.txt");
    fs::write(&src, b"hello").unwrap();
    let out = iish(
        &format!("cp {} {}\n", src.display(), dst.display()),
        &["--allow", "cp"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read(&dst).unwrap(), b"hello");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn subprocess_tier_denied_by_default_with_no() {
    let out = iish("uname -a\n", &["--no"]);
    assert!(!out.status.success());
}

#[test]
fn config_file_subprocess_allow_is_honored() {
    let dir = scratch("config-file");
    fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");
    fs::write(&config_path, "[defaults]\nsubprocess = \"allow\"\n").unwrap();
    let target = dir.join("stamped");

    let out = iish_raw(
        &format!("touch {}\n", target.display()),
        &["--config", config_path.to_str().unwrap()],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(target.is_file());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cli_deny_overrides_a_natively_implemented_command() {
    let out = iish("curl https://example.com\n", &["--deny", "curl"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("denied"), "stderr: {}", stderr(&out));
}

#[test]
fn dry_run_reports_but_executes_nothing() {
    let base = scratch("dryrun");
    let script = format!("mkdir {0}\nrm -r {0}\n", base.display());
    let out = iish(&script, &["--dry-run"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!base.exists(), "--dry-run must not touch the filesystem");
    let report = stdout(&out);
    assert!(report.contains("ALLOW"), "report: {report}");
    // The simulated ledger lets the dry run see that `rm` targets a
    // directory the script itself would have created.
    assert!(
        report.contains("deletes only paths this script created"),
        "report: {report}"
    );
}

#[test]
fn chmod_of_created_file_works_and_foreign_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let base = scratch("chmod");
    let url = serve(b"#!/bin/true\n", 1);
    let script = format!(
        "mkdir -p {0}\ncurl -fsSLo {0}/tool {url}\nchmod 755 {0}/tool\n",
        base.display()
    );
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let mode = fs::metadata(base.join("tool"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
    fs::remove_dir_all(&base).unwrap();

    let out = iish("chmod 777 /etc/hostname\n", &[]);
    assert!(!out.status.success());
}

#[test]
fn fetch_downloads_to_new_file() {
    let base = scratch("fetch");
    fs::create_dir_all(&base).unwrap(); // pre-existing parent, new file
    let url = serve(b"payload-bytes", 1);
    let target = base.join("out.bin");
    let out = iish(&format!("curl -fsSLo {} {url}\n", target.display()), &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read(&target).unwrap(), b"payload-bytes");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn fetch_to_stdout_streams_the_body() {
    let url = serve(b"streamed", 1);
    let out = iish(&format!("curl -fsSL {url}\n"), &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "streamed");
}

#[test]
fn overwrite_prompt_is_fatal_with_no_and_honored_with_yes() {
    let base = scratch("overwrite");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("existing.txt");
    fs::write(&target, b"original").unwrap();

    let url = serve(b"replaced", 2);
    let script = format!("curl -o {} {url}\n", target.display());

    let out = iish(&script, &["--no"]);
    assert!(!out.status.success());
    assert_eq!(fs::read(&target).unwrap(), b"original");

    let out = iish(&script, &["--yes"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read(&target).unwrap(), b"replaced");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn prompt_without_tty_or_flags_fails_closed() {
    let base = scratch("no-tty");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("existing.txt");
    fs::write(&target, b"original").unwrap();

    // No --yes/--no: iish must try /dev/tty. Under a test harness there
    // is usually no controlling terminal; if this environment has one,
    // we can't answer it non-interactively, so only assert when absent.
    if fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
    {
        fs::remove_dir_all(&base).unwrap();
        return;
    }
    let url = serve(b"replaced", 1);
    let out = iish(&format!("curl -o {} {url}\n", target.display()), &[]);
    assert!(!out.status.success());
    assert_eq!(fs::read(&target).unwrap(), b"original");
    assert!(stderr(&out).contains("--yes"), "stderr: {}", stderr(&out));
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn printf_output_matches_bash_subset() {
    let out = iish("printf '%s=%s\\n' key value\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "key=value\n");
}

#[test]
fn script_file_argument_is_supported() {
    let base = scratch("file-arg");
    fs::create_dir_all(&base).unwrap();
    let script_path = base.join("install.sh");
    fs::write(&script_path, "echo from-a-file\n").unwrap();
    let out = iish("", &[script_path.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "from-a-file\n");
    fs::remove_dir_all(&base).unwrap();
}
