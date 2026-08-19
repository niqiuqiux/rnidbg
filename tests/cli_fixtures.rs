//! Drive the shipped `rnidbg` binary against the ARM64 fixtures.
//! These tests require `android/sdk36/system/lib64/libc.so`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sdk_libc() -> PathBuf {
    repo_root().join("android/sdk36/system/lib64/libc.so")
}

fn require_sdk() {
    let libc = sdk_libc();
    assert!(
        libc.is_file(),
        "Android 36 libc missing at {} — run android/sdk36/pull.ps1",
        libc.display()
    );
}

fn rnidbg() -> Command {
    let root = repo_root();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rnidbg"));
    cmd.current_dir(&root);
    cmd.env("BASE_PATH", root.join("android/sdk36"));
    cmd.env("RUST_LOG", "info");
    cmd
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = rnidbg()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn rnidbg {args:?}: {e}"));
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn exec_hello_prints_greeting_and_exits_0() {
    require_sdk();
    assert!(Path::new("tests/fixtures/arm64/hello").is_file()
        || repo_root().join("tests/fixtures/arm64/hello").is_file());
    for pass in 1..=2 {
        let (code, stdout, stderr) = run(&["exec", "--bin", "tests/fixtures/arm64/hello"]);
        assert_eq!(
            code, 0,
            "hello pass {pass} host exit {code}\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stdout.contains("hello from rnidbg"),
            "hello pass {pass} missing greeting\nstdout={stdout:?}\nstderr={stderr}"
        );
    }
}

#[test]
fn jni_onload_ok() {
    require_sdk();
    for pass in 1..=2 {
        let (code, stdout, stderr) =
            run(&["jni", "--so", "tests/fixtures/arm64/libnative.so", "--onload"]);
        let logs = format!("{stdout}{stderr}");
        assert_eq!(
            code, 0,
            "jni pass {pass} host exit {code}\n{logs}"
        );
        assert!(
            logs.contains("JNI_OnLoad ok"),
            "jni pass {pass} missing JNI_OnLoad ok\n{logs}"
        );
    }
}

#[test]
fn exec_printf_pie_prints_phrase_and_exits_0() {
    require_sdk();
    let bin = repo_root().join("tests/fixtures/arm64/printf");
    assert!(bin.is_file(), "missing {}", bin.display());
    for pass in 1..=2 {
        let (code, stdout, stderr) = run(&["exec", "--bin", "tests/fixtures/arm64/printf"]);
        assert_eq!(
            code, 0,
            "printf pie pass {pass} host exit {code}\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(
            stdout.contains("complete pie from rnidbg"),
            "printf pie pass {pass} missing phrase\nstdout={stdout:?}\nstderr={stderr}"
        );
    }
}

#[test]
fn exec_test_host_exits_0() {
    require_sdk();
    for pass in 1..=3 {
        let (code, stdout, stderr) = run(&["exec", "--bin", "tests/fixtures/arm64/test"]);
        assert_eq!(
            code, 0,
            "test pass {pass} host exit {code}\nstdout={stdout}\nstderr={stderr}"
        );
    }
}

#[test]
fn jni_hwdetect_loads_and_calls_export() {
    require_sdk();
    let so = repo_root().join("tests/fixtures/arm64/libhwdetect.so");
    assert!(so.is_file(), "missing {}", so.display());
    let (code, stdout, stderr) = run(&[
        "jni",
        "--so",
        "tests/fixtures/arm64/libhwdetect.so",
        "--call",
        "Java_com_niqiuqiux_androidhwdetect_MainActivity_runHardwareBreakpointCheck",
    ]);
    let logs = format!("{stdout}{stderr}");
    assert_eq!(code, 0, "hwdetect host exit {code}\n{logs}");
    assert!(
        logs.contains("loaded libhwdetect.so"),
        "missing load line\n{logs}"
    );
    assert!(
        logs.contains("JNI Java_com_niqiuqiux_androidhwdetect_MainActivity_runHardwareBreakpointCheck"),
        "missing JNI call line\n{logs}"
    );
    assert!(
        logs.contains("\"maxScore\":280") && logs.contains("\"items\":["),
        "JNI did not return the hardware-detect JSON report\n{logs}"
    );
    // Three UE4 workers must actually run (prctl + gettid + heartbeat).
    // Without the usleep yield they stay queued and the report scores 0/280.
    for tid in ["tid=2668", "tid=2669", "tid=2670"] {
        assert!(
            logs.contains(tid),
            "hwdetect missing worker {tid}\n{logs}"
        );
    }
    assert!(
        logs.contains("heartbeat=1"),
        "hwdetect workers did not increment heartbeat\n{logs}"
    );
    // Cooperative fork + ptrace: stage 7, 6 BP / 4 WP, SIGTRAP in worker
    // execution order, and /proc/self/task/<tid>/comm for the final snapshot.
    assert!(
        logs.contains("stage=7") && logs.contains("BP=6"),
        "hwdetect ptrace self-check did not finish stage 7 / 6 BP slots\n{logs}"
    );
    assert!(
        logs.contains("\"score\":280") && logs.contains("\"maxScore\":280"),
        "hwdetect score did not reach 280/280\n{logs}"
    );
}
