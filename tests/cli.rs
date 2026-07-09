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

/// Like `iish`, but with `$HOME` overridden to `home` — for env-file
/// append tests, which must never touch the real invoking user's rc
/// files.
fn iish_with_home(script: &str, args: &[&str], home: &std::path::Path) -> Output {
    let mut all_args = vec!["--no-config"];
    all_args.extend_from_slice(args);
    let mut command = Command::new(env!("CARGO_BIN_EXE_iish"));
    for var in ["http_proxy", "https_proxy", "all_proxy"] {
        command.env_remove(var).env_remove(var.to_uppercase());
    }
    command.env("HOME", home);
    let mut child = command
        .args(&all_args)
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
    let base = scratch("touch-subprocess");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("touched.txt");
    let out = iish(
        &format!("touch {}\n", target.display()),
        &["--allow", "touch"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(target.is_file(), "the real `touch` binary should have run");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn cp_copies_natively_without_the_subprocess_tier() {
    let base = scratch("cp-native");
    fs::create_dir_all(&base).unwrap();
    let src = base.join("src.txt");
    let dst = base.join("dst.txt");
    fs::write(&src, b"hello").unwrap();
    // Note the absence of `--allow cp`/`--subprocess=allow`: a native
    // `cp` to a brand-new destination needs no policy confirmation at
    // all, unlike the generic subprocess tier.
    let out = iish(&format!("cp {} {}\n", src.display(), dst.display()), &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read(&dst).unwrap(), b"hello");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn cp_overwriting_a_foreign_file_is_refused_with_no() {
    let base = scratch("cp-native-overwrite");
    fs::create_dir_all(&base).unwrap();
    let src = base.join("src.txt");
    let dst = base.join("dst.txt");
    fs::write(&src, b"new").unwrap();
    fs::write(&dst, b"old").unwrap();
    let out = iish(
        &format!("cp {} {}\n", src.display(), dst.display()),
        &["--no"],
    );
    assert!(!out.status.success());
    assert_eq!(
        fs::read(&dst).unwrap(),
        b"old",
        "a declined overwrite must leave the pre-existing file untouched"
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn cp_recursive_copies_a_directory_tree() {
    let base = scratch("cp-native-recursive");
    let src_dir = base.join("src");
    fs::create_dir_all(src_dir.join("nested")).unwrap();
    fs::write(src_dir.join("nested/file.txt"), b"payload").unwrap();
    let dst_dir = base.join("dst");

    let out = iish(
        &format!("cp -r {} {}\n", src_dir.display(), dst_dir.display()),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        fs::read(dst_dir.join("nested/file.txt")).unwrap(),
        b"payload"
    );
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

#[test]
fn env_file_append_writes_restricted_grammar_with_yes() {
    let home = scratch("env-home");
    fs::create_dir_all(&home).unwrap();
    let out = iish_with_home(
        "echo 'export PATH=\"/opt/tool/bin:$PATH\"' >> ~/.bashrc\n",
        &["--yes"],
        &home,
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        fs::read_to_string(home.join(".bashrc")).unwrap(),
        "export PATH=\"/opt/tool/bin:$PATH\"\n"
    );
    fs::remove_dir_all(&home).unwrap();
}

#[test]
fn env_file_append_declined_with_no_leaves_no_file() {
    let home = scratch("env-home-no");
    fs::create_dir_all(&home).unwrap();
    let out = iish_with_home("echo 'export FOO=bar' >> ~/.bashrc\n", &["--no"], &home);
    assert!(!out.status.success());
    assert!(!home.join(".bashrc").exists());
    fs::remove_dir_all(&home).unwrap();
}

#[test]
fn env_file_append_rejects_lines_outside_the_grammar() {
    let home = scratch("env-home-bad");
    fs::create_dir_all(&home).unwrap();
    let out = iish_with_home("echo 'rm -rf /' >> ~/.bashrc\n", &["--yes"], &home);
    assert!(!out.status.success());
    assert!(!home.join(".bashrc").exists());
    fs::remove_dir_all(&home).unwrap();
}

#[test]
fn env_file_append_rejects_files_outside_home() {
    let base = scratch("env-outside");
    fs::create_dir_all(&base).unwrap();
    let target = base.join(".bashrc");
    let out = iish(
        &format!("echo 'export FOO=bar' >> {}\n", target.display()),
        &["--yes"],
    );
    assert!(!out.status.success());
    assert!(!target.exists());
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn sha256sum_check_verifies_a_downloaded_file_against_a_downloaded_checksum() {
    let base = scratch("sha256-e2e");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("payload.bin");
    let checklist = base.join("payload.bin.sha256");

    let payload_url = serve(b"hello-world", 1);
    let checksum_line = format!(
        "afa27b44d43b02a9fea41d13cedc2e4016cfcf87c5dbf990e593669aa8ce286d  {}",
        target.display()
    );
    let checksum_body: &'static [u8] = Box::leak(checksum_line.into_bytes().into_boxed_slice());
    let checksum_url = serve(checksum_body, 1);

    let script = format!(
        "curl -fsSLo {t} {payload_url}\ncurl -fsSLo {c} {checksum_url}\nsha256sum -c {c}\n",
        t = target.display(),
        c = checklist.display(),
    );
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains(&format!("{}: OK", target.display())),
        "stdout: {}",
        stdout(&out)
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn sha256sum_check_fails_on_mismatch() {
    let base = scratch("sha256-mismatch");
    fs::create_dir_all(&base).unwrap();
    let target = base.join("payload.bin");
    let checklist = base.join("payload.bin.sha256");

    let payload_url = serve(b"tampered-content", 1);
    let checksum_line = format!("{}  {}", "0".repeat(64), target.display());
    let checksum_body: &'static [u8] = Box::leak(checksum_line.into_bytes().into_boxed_slice());
    let checksum_url = serve(checksum_body, 1);

    let script = format!(
        "curl -fsSLo {t} {payload_url}\ncurl -fsSLo {c} {checksum_url}\nsha256sum -c {c}\n",
        t = target.display(),
        c = checklist.display(),
    );
    let out = iish(&script, &[]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("FAILED"), "stdout: {}", stdout(&out));
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn sha256sum_refuses_files_this_script_did_not_create() {
    let base = scratch("sha256-foreign");
    fs::create_dir_all(&base).unwrap();
    let foreign = base.join("existing.txt");
    fs::write(&foreign, b"not ours").unwrap();
    let out = iish(&format!("sha256sum {}\n", foreign.display()), &[]);
    assert!(!out.status.success());
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn set_eu_is_a_recognized_no_op() {
    let out = iish("set -eu\necho still-running\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "still-running\n");
}

#[test]
fn set_unknown_flag_aborts_the_run() {
    let out = iish("set -k\necho should-not-print\n", &[]);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), "");
}

#[test]
fn brace_group_runs_its_statements_against_the_live_session() {
    let base = scratch("brace-group");
    let script = format!(
        "{{ mkdir -p {0}; echo inside; }}\nrm -r {0}\n",
        base.display()
    );
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "inside\n");
    assert!(
        !base.exists(),
        "the rm after the group should see the dir the group created"
    );
}

#[test]
fn brace_group_stops_the_whole_run_on_a_denial_inside_it() {
    let out = iish("{ echo one; sudo rm -rf /; echo two; }\n", &[]);
    assert!(!out.status.success());
    assert_eq!(
        stdout(&out),
        "one\n",
        "the statement before the denial should have run, but not the one after"
    );
}

#[test]
fn defining_a_function_has_no_effect_until_it_is_called() {
    let out = iish("greet() { echo hello; }\necho before-call\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "before-call\n",
        "the definition alone must not run the body"
    );
}

#[test]
fn calling_a_defined_function_runs_its_body() {
    let out = iish("greet() { echo hello from greet; }\ngreet\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "hello from greet\n");
}

#[test]
fn a_later_function_definition_replaces_an_earlier_one() {
    let out = iish("f() { echo first; }\nf() { echo second; }\nf\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "second\n");
}

#[test]
fn self_recursive_function_is_refused_instead_of_overflowing_the_stack() {
    let out = iish("f() { f; }\nf\n", &[]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("deep"), "stderr: {}", stderr(&out));
}
