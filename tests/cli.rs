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
fn cp_copies_a_source_reached_through_a_symlinked_directory() {
    // The merged-usr shape (`/bin -> usr/bin` on Debian and friends):
    // copying *out of* a symlinked directory is an ordinary read, not a
    // symlink escape, and real installers do it all the time.
    let base = scratch("cp-src-symlinked-bin");
    fs::create_dir_all(base.join("usr/bin")).unwrap();
    fs::write(base.join("usr/bin/tool"), b"tool bytes").unwrap();
    std::os::unix::fs::symlink("usr/bin", base.join("bin")).unwrap();
    let dst = base.join("installed-tool");
    let out = iish(
        &format!("cp {}/bin/tool {}\n", base.display(), dst.display()),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read(&dst).unwrap(), b"tool bytes");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn stderr_redirect_to_dev_null_silences_a_subprocess() {
    let base = scratch("stderr-devnull");
    // `ls` of a missing path exits non-zero and complains on stderr;
    // `|| true` keeps the failure from aborting the run, so the only
    // question left is whether the complaint itself was discarded.
    // (iish echoes each statement it runs — including the path — on its
    // own stderr, so the assertions look for ls's complaint text, which
    // only the child process produces.)
    let script = format!("ls {}/missing 2> /dev/null || true\n", base.display());
    let out = iish(&script, &["--yes"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        !stderr(&out).contains("No such file"),
        "the subprocess's stderr must go to /dev/null, got: {}",
        stderr(&out)
    );

    // Same command without the redirect: the complaint comes through,
    // proving the quiet run above was the redirect's doing.
    let noisy = iish(
        &format!("ls {}/missing || true\n", base.display()),
        &["--yes"],
    );
    assert!(noisy.status.success(), "stderr: {}", stderr(&noisy));
    assert!(
        stderr(&noisy).contains("No such file"),
        "without the redirect the complaint should reach stderr, got: {}",
        stderr(&noisy)
    );
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

#[test]
fn if_true_runs_the_then_branch_not_the_else() {
    let out = iish("if true; then echo yes; else echo no; fi\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "yes\n");
}

#[test]
fn if_false_runs_the_else_branch() {
    // `false` has no native implementation, so it would need the
    // subprocess-tier's `ask` policy (no tty in tests); `[ 1 -eq 2 ]` is
    // a false condition iish evaluates natively instead.
    let out = iish("if [ 1 -eq 2 ]; then echo yes; else echo no; fi\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "no\n");
}

#[test]
fn elif_chain_picks_the_first_true_clause() {
    let out = iish(
        "if [ 1 -eq 2 ]; then echo a; elif true; then echo b; else echo c; fi\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "b\n");
}

#[test]
fn if_with_no_matching_branch_and_no_else_runs_nothing() {
    let out = iish("if [ 1 -eq 2 ]; then echo yes; fi\necho after\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "after\n");
}

#[test]
fn bracket_test_condition_checks_the_real_filesystem() {
    let base = scratch("if-bracket");
    fs::create_dir_all(&base).unwrap();
    let script = format!(
        "if [ -d {0} ]; then echo is-a-dir; else echo not-a-dir; fi\n",
        base.display()
    );
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "is-a-dir\n");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn condition_side_effects_are_visible_to_later_statements() {
    let base = scratch("if-condition-mkdir");
    let script = format!(
        "if mkdir -p {0}; then echo made; fi\nrm -r {0}\n",
        base.display()
    );
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "made\n",
        "mkdir in the condition should have actually run, and the later rm should see it"
    );
    assert!(!base.exists());
}

#[test]
fn a_denial_inside_an_if_condition_aborts_the_whole_run() {
    let out = iish("if sudo rm -rf /; then echo yes; fi\necho after\n", &[]);
    assert!(!out.status.success());
    assert_eq!(
        stdout(&out),
        "",
        "the condition's denial should abort before any branch or later statement runs"
    );
}

#[test]
fn a_nonzero_subprocess_in_a_condition_does_not_abort_the_run() {
    let out = iish(
        "if false; then echo yes; fi\necho still-running\n",
        &["--allow", "false"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "still-running\n");
}

#[test]
fn case_dispatches_to_the_matching_arm_and_runs_it() {
    let out = iish(
        "case linux in linux) echo is-linux;; *) echo other;; esac\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "is-linux\n");
}

#[test]
fn case_glob_pattern_dispatches_to_the_matching_arm() {
    let out = iish(
        "case linux-x86_64 in linux*) echo matched-prefix;; *) echo default;; esac\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "matched-prefix\n");
}

#[test]
fn case_with_no_matching_arm_is_a_noop() {
    let out = iish("case linux in darwin) echo yes;; esac\necho after\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "after\n");
}

#[test]
fn and_runs_the_second_command_only_when_the_first_succeeds() {
    let out = iish("[ 1 -eq 1 ] && echo yes\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "yes\n");
}

#[test]
fn and_short_circuits_and_survives_when_the_second_command_never_runs() {
    // Matches real bash under `set -e`: `false && echo hi; echo after`
    // prints "after" -- `echo hi`, the last pipeline in the list, never
    // ran, so its (never-produced) failure can't trip errexit.
    let out = iish("[ 1 -eq 2 ] && echo yes\necho after\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "after\n");
}

#[test]
fn and_aborts_when_the_last_pipeline_runs_and_fails() {
    // `true && false` does NOT survive `set -e`: `false` is the last
    // pipeline in the list, and it actually ran.
    let out = iish("true && [ 1 -eq 2 ]\necho after\n", &[]);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), "");
}

#[test]
fn or_runs_the_fallback_only_when_the_first_fails() {
    let out = iish("[ 1 -eq 2 ] || echo fallback\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "fallback\n");
}

#[test]
fn or_skips_the_fallback_when_the_first_succeeds() {
    let out = iish("[ 1 -eq 1 ] || echo fallback\necho after\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "after\n");
}

#[test]
fn or_fallback_pattern_survives_when_the_fallback_succeeds() {
    // The extremely common installer idiom: `probe || fallback`. If the
    // probe fails but the fallback succeeds, the whole line succeeds and
    // the script keeps going.
    let out = iish("[ 1 -eq 2 ] || echo fallback\necho still-running\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "fallback\nstill-running\n");
}

#[test]
fn command_list_condition_side_effects_persist_across_short_circuit() {
    let base = scratch("and-or-mkdir");
    let script = format!("[ -d {0} ] || mkdir -p {0}\nrm -r {0}\n", base.display());
    let out = iish(&script, &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(!base.exists());
}

#[test]
fn and_or_list_works_as_an_if_condition() {
    let out = iish(
        "if [ 1 -eq 2 ] || true; then echo yes; else echo no; fi\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "yes\n");
}

#[test]
fn a_denial_inside_a_command_list_aborts_the_whole_run() {
    let out = iish("sudo rm -rf / || echo fallback\necho after\n", &[]);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), "");
}

#[test]
fn bare_assignment_can_be_read_back_by_echo() {
    let out = iish("FOO=\"hello world\"\necho $FOO\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "hello world\n");
}

#[test]
fn later_assignment_replaces_an_earlier_one() {
    let out = iish("FOO=first\nFOO=second\necho $FOO\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "second\n");
}

#[test]
fn assigned_variable_can_drive_an_if_condition() {
    let out = iish(
        "OS=linux\nif [ \"$OS\" = linux ]; then echo yes; else echo no; fi\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "yes\n");
}

#[test]
fn assigned_variable_can_drive_a_case_value() {
    let out = iish(
        "OS=linux\ncase \"$OS\" in linux) echo is-linux;; *) echo other;; esac\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "is-linux\n");
}

#[test]
fn unset_variable_expands_empty_unless_the_script_sets_nounset() {
    // bash's default: an unset variable expands to empty.
    let out = iish("echo one$NOT_ASSIGNED_ANYWHERE_IISH.two\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "one.two\n");

    // The script's own `set -u` makes the same reference fatal.
    let out = iish("set -u\necho $NOT_ASSIGNED_ANYWHERE_IISH\n", &[]);
    assert!(!out.status.success());
    assert_eq!(stdout(&out), "");
}

// ---------------------------------------------------------------------
// Milestone 7 features: functions with arguments, `local`, loops,
// command substitution, pipelines, `!`, control flow, `cd`, and the
// expansions installers lean on.
// ---------------------------------------------------------------------

#[test]
fn function_arguments_bind_positional_parameters() {
    let out = iish(
        "greet() { echo \"hello $1 (of $#)\"; }\ngreet world extra\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "hello world (of 2)\n");
}

#[test]
fn at_expansion_forwards_argument_boundaries() {
    let out = iish(
        "inner() { echo \"$#:$1|$2\"; }\nouter() { inner \"$@\"; }\nouter one 'two words'\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "2:one|two words\n");
}

#[test]
fn local_scopes_to_the_call_and_return_sets_the_status() {
    let out = iish(
        concat!(
            "X=global\n",
            "f() { local X=inner; echo \"in: $X\"; return 3; }\n",
            "if f; then echo returned-true; else echo returned-false; fi\n",
            "echo \"out: $X\"\n",
        ),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "in: inner\nreturned-false\nout: global\n");
}

#[test]
fn local_outside_a_function_is_refused() {
    let out = iish("local X=1\n", &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("outside a function"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn for_loop_iterates_with_break_and_continue() {
    let out = iish(
        concat!(
            "for x in a b c d; do\n",
            "  if [ \"$x\" = b ]; then continue; fi\n",
            "  if [ \"$x\" = d ]; then break; fi\n",
            "  echo \"got $x\"\n",
            "done\n",
        ),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "got a\ngot c\n");
}

#[test]
fn while_loop_with_shift_walks_arguments() {
    let out = iish(
        "args() { while [ \"$#\" -gt 0 ]; do echo \"arg $1\"; shift; done; }\nargs x y\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "arg x\narg y\n");
}

#[test]
fn until_loop_runs_until_the_condition_holds() {
    let out = iish(
        "V=start\nuntil [ \"$V\" = done ]; do echo tick; V=done; done\necho after\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "tick\nafter\n");
}

#[test]
fn command_substitution_captures_native_output() {
    let out = iish("GREETING=$(echo hello)\necho \"got: ${GREETING}\"\n", &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "got: hello\n");
}

#[test]
fn command_substitution_captures_a_subprocess_and_a_function() {
    let out = iish(
        concat!(
            "os=$(uname -s)\n",
            "shout() { echo \"OS=$os\"; }\n",
            "LINE=$(shout)\n",
            "echo \"$LINE\"\n",
        ),
        &["--allow", "uname"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "OS=Linux\n");
}

#[test]
fn command_substitution_inside_dry_run_is_reported_not_run() {
    let out = iish("V=$(echo hi)\n", &["--dry-run"]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("--dry-run"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn pipeline_feeds_captured_output_between_stages() {
    let out = iish(
        "echo HELLO | tr '[:upper:]' '[:lower:]'\n",
        &["--allow", "tr"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "hello\n");
}

#[test]
fn pipeline_with_a_function_stage_works() {
    let out = iish(
        "produce() { echo ABC; }\nX=$(produce | tr '[:upper:]' '[:lower:]')\necho \"$X\"\n",
        &["--allow", "tr"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "abc\n");
}

#[test]
fn piping_a_dangerous_command_into_a_shell_is_vetted_and_refused() {
    // `… | sh` is no longer a blanket refusal: iish captures what the
    // producer emitted and interprets it (sub-iish). Here that captured
    // text is `rm -rf /`, which iish refuses just as it would inline --
    // so the run still fails, now for the right, specific reason.
    let out = iish("echo 'rm -rf /' | sh\n", &["--yes"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("refusing") && stderr(&out).contains("rm -rf /"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn bang_negates_a_condition_without_aborting() {
    let out = iish(
        "if ! [ -d /definitely-not-a-real-dir-iish ]; then echo absent; fi\n! true\necho survived\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "absent\nsurvived\n");
}

#[test]
fn exit_ends_the_run_with_the_given_status() {
    let out = iish("echo before\nexit 7\necho after\n", &[]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(stdout(&out), "before\n");
}

#[test]
fn cd_changes_the_directory_for_later_statements() {
    let dir = scratch("cd-target");
    fs::create_dir_all(&dir).unwrap();
    let out = iish(
        &format!(
            "cd {}\necho \"now in $PWD\" > /dev/null\npwd\n",
            dir.display()
        ),
        &["--allow", "pwd"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out)
            .trim_end()
            .ends_with(dir.file_name().unwrap().to_str().unwrap()),
        "stdout: {}",
        stdout(&out)
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn default_value_and_pattern_removal_expansions() {
    let out = iish(
        concat!(
            "V=${UNSET_IISH_X:-fallback}\n",
            "P=/usr/local/bin/tool\n",
            "echo \"$V ${P##*/} ${P%/*}\"\n",
        ),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "fallback tool /usr/local/bin\n");
}

#[test]
fn command_v_reports_functions_and_missing_commands() {
    let out = iish(
        concat!(
            "mine() { echo x; }\n",
            "if command -v mine > /dev/null; then echo have-mine; fi\n",
            "if ! command -v iish-not-a-real-cmd > /dev/null; then echo missing; fi\n",
        ),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "have-mine\nmissing\n");
}

#[test]
fn cat_heredoc_prints_its_banner() {
    let out = iish(
        "cat << EOF\nbanner line one\n  line two\nEOF\necho after\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "banner line one\n  line two\nafter\n");
}

#[test]
fn read_from_dev_null_fails_like_bash() {
    let out = iish(
        "if read -r answer < /dev/null; then echo read-ok; else echo no-input; fi\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "no-input\n");
}

#[test]
fn question_mark_tracks_the_last_status() {
    let out = iish(
        "false || true\nif [ \"$?\" -eq 0 ]; then echo zero; fi\n",
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "zero\n");
}

#[test]
fn unset_removes_a_variable_and_a_function() {
    let out = iish(
        concat!(
            "f() { echo from-function; }\n",
            "unset -f f\n",
            "V=set\nunset V\n",
            "echo \"v=${V:-gone}\"\n",
        ),
        &[],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "v=gone\n");
}

#[test]
fn runaway_recursion_via_substitution_is_refused() {
    let out = iish("f() { X=$(f); }\nf\n", &[]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("deep"), "stderr: {}", stderr(&out));
}

// ---------------------------------------------------------------------
// The "green path" for a realistic installer: a script shaped like a
// real one — function definitions and calls, `case`-based platform
// detection, `local`, a real HTTP download, `chmod +x`, and a PATH
// export into an rc file — runs to completion through iish and leaves
// behind a working program. This is the end state the whole corpus is
// working toward (PLAN.md milestone 7); proving it here, through the
// real binary against a real (local) HTTP server, shows the harness
// and iish can actually reach a completed, verified install.
// ---------------------------------------------------------------------
#[test]
fn a_realistic_download_installer_runs_to_completion_and_installs_a_working_tool() {
    let base = scratch("realistic-install");
    let home = base.join("home");
    let prefix = base.join("opt/mytool");
    fs::create_dir_all(&home).unwrap();

    // The payload is a tiny shell program the "installer" downloads,
    // marks executable, and puts on PATH — standing in for a real
    // downloaded binary.
    let payload = b"#!/bin/sh\necho mytool-1.0\n";
    let url = serve(payload, 1);

    let script = format!(
        r#"
set -eu

detect_platform() {{
    case "$(uname -s)" in
        Linux*) echo linux ;;
        Darwin*) echo darwin ;;
        *) echo unknown ;;
    esac
}}

install() {{
    local prefix="$1"
    local plat
    plat="$(detect_platform)"
    echo "installing for ${{plat}}"
    mkdir -p "${{prefix}}/bin"
    curl -fsSL "{url}" -o "${{prefix}}/bin/mytool"
    chmod +x "${{prefix}}/bin/mytool"
    echo "export PATH=\"${{prefix}}/bin:$PATH\"" >> "$HOME/.profile"
}}

for candidate in "{prefix_disp}"; do
    install "$candidate"
done
echo done
"#,
        url = url,
        prefix_disp = prefix.display(),
    );

    let out = iish_with_home(&script, &["--yes", "--allow", "uname"], &home);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    // The install completed: the tool is on disk, executable, and runs.
    let tool = prefix.join("bin/mytool");
    assert!(tool.is_file(), "the downloaded tool should exist");
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        fs::metadata(&tool).unwrap().permissions().mode() & 0o111,
        0,
        "the tool should be executable"
    );
    let run = Command::new(&tool).output().expect("tool should run");
    assert_eq!(String::from_utf8_lossy(&run.stdout), "mytool-1.0\n");

    // And the PATH export landed in the rc file via the env-file grammar.
    let profile = fs::read_to_string(home.join(".profile")).unwrap();
    assert!(
        profile.contains("mytool/bin"),
        "the PATH export should have been appended: {profile}"
    );

    fs::remove_dir_all(&base).unwrap();
}

// ---------------------------------------------------------------------
// `curl … | sh` as a sub-context ("sub-iish"): instead of refusing the
// pipe-into-a-shell pattern, iish runs the producer, captures the
// downloaded script, and interprets it itself under the same policy --
// recursively transparent, the way command substitution already is.
// ---------------------------------------------------------------------
#[test]
fn curl_pipe_sh_interprets_the_downloaded_second_stage() {
    let home = scratch("subiish-home");
    fs::create_dir_all(&home).unwrap();
    // The second stage does real (allowed) work under $HOME.
    let stage2 = b"#!/bin/sh\nmkdir -p \"$HOME/installed-by-substage\"\necho stage2-ran\n";
    let url = serve(stage2, 1);

    let out = iish_with_home(
        &format!("echo before\ncurl -fsSL {url} | sh\necho after\n"),
        &["--yes"],
        &home,
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // The producer ran, the second stage was interpreted by iish, and
    // the whole outer script continued afterward.
    assert_eq!(stdout(&out), "before\nstage2-ran\nafter\n");
    assert!(
        home.join("installed-by-substage").is_dir(),
        "the second stage's side effects should have been applied"
    );
    fs::remove_dir_all(&home).unwrap();
}

#[test]
fn curl_pipe_sh_still_vets_the_second_stage_and_refuses_danger() {
    let home = scratch("subiish-danger-home");
    fs::create_dir_all(&home).unwrap();
    // A second stage that tries to delete something this run never
    // created: the sub-context must refuse it exactly as a top-level
    // statement would, aborting the run.
    let evil = b"#!/bin/sh\nrm -rf /etc/hostname\n";
    let url = serve(evil, 1);

    let out = iish_with_home(&format!("curl -fsSL {url} | sh\n"), &["--yes"], &home);
    assert!(
        !out.status.success(),
        "a dangerous second stage must abort the run"
    );
    assert!(
        stderr(&out).contains("refusing"),
        "stderr should show the refusal: {}",
        stderr(&out)
    );
    // Whatever came before is fine; the point is the rm was refused.
    assert!(
        std::path::Path::new("/etc/hostname").exists(),
        "the refused rm must not have run"
    );
    fs::remove_dir_all(&home).unwrap();
}

#[test]
fn sh_dash_c_after_a_pipe_is_not_treated_as_sub_iish() {
    // Only a stdin-reading shell (`curl | sh`) maps to "interpret the
    // piped script". `| sh -c '…'` is a different shape and stays refused.
    let url = serve(b"echo x\n", 1);
    let out = iish(&format!("curl -fsSL {url} | sh -c 'echo hi'\n"), &["--yes"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not supported"),
        "stderr: {}",
        stderr(&out)
    );
}
