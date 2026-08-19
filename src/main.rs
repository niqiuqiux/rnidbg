use anyhow::{anyhow, Result};
use emulator::android::sdk::{ANDROID_SDK, DEFAULT_SDK_ROOT};
use emulator::AndroidEmulator;
use log::{error, info};
use std::env;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or_else(|_| "info".into()));
    env_logger::init();

    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            error!("{err:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<i32> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        return Ok(0);
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "exec" => cmd_exec(&args),
        "jni" => cmd_jni(&args),
        other => Err(anyhow!("unknown command '{other}'")),
    }
}

fn print_usage() {
    eprintln!(
        "rnidbg — ARM64 Android {ANDROID_SDK} userland runtime\n\n\
         Usage:\n\
           rnidbg exec --bin <path> [--] [args...]\n\
           rnidbg jni  --so <path> [--onload] [--call <Java_symbol>]\n\n\
         Environment:\n\
           BASE_PATH   Android system root (default {DEFAULT_SDK_ROOT})\n\
           RUST_LOG    log filter (default info)\n"
    );
}

fn cmd_exec(args: &[String]) -> Result<i32> {
    let (bin, rest) = parse_flag_path(args, "--bin")?;
    let extra: Vec<&str> = rest.iter().map(String::as_str).collect();
    ensure_sdk_root()?;

    let emu = AndroidEmulator::create_arm64(2667, 2427, Path::new(&bin).file_name().and_then(|s| s.to_str()).unwrap_or("a.out"), ());
    emu.set_exec_path(&bin);
    let module_cell = emu.load_library(&bin, true)?;
    if let Some(code) = emu.last_exit_status() {
        info!("exited during load: {code}");
        emulator::terminate_host(code);
    }
    let module = unsafe { &*module_cell.get() };
    let code = module.call_entry(&emu, &extra)?;
    info!("exit code: {code}");
    emulator::terminate_host(code);
}

fn cmd_jni(args: &[String]) -> Result<i32> {
    let (so, rest) = parse_flag_path(args, "--so")?;
    let onload = rest.iter().any(|a| a == "--onload");
    let call = parse_optional_flag(&rest, "--call")?;
    ensure_sdk_root()?;

    let emu = AndroidEmulator::create_arm64(2667, 2427, "rnidbg", ());
    let vm = emu.create_jni_env();
    let module_cell = vm.load_library(emu.clone(), &so, true)?;
    let module = unsafe { &*module_cell.get() };
    info!("loaded {} base=0x{:x}", module.name, module.base);
    if onload {
        vm.call_jni_onload(emu.clone(), module)?;
        info!("JNI_OnLoad ok");
    }
    if let Some(symbol) = call {
        let value = vm.call_jni_export(emu.clone(), module, &symbol)?;
        info!("JNI {symbol} => {}", value.to_string());
    }
    emulator::terminate_host(0);
}

fn parse_optional_flag(args: &[String], flag: &str) -> Result<Option<String>> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            let value = args
                .get(i + 1)
                .cloned()
                .ok_or_else(|| anyhow!("{flag} requires a symbol name"))?;
            if value.starts_with("--") {
                return Err(anyhow!("{flag} requires a symbol name"));
            }
            return Ok(Some(value));
        }
        i += 1;
    }
    Ok(None)
}

fn parse_flag_path<'a>(args: &'a [String], flag: &str) -> Result<(String, Vec<String>)> {
    let mut path = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            i += 1;
            path = Some(args.get(i).cloned().ok_or_else(|| anyhow!("{flag} requires a path"))?);
        } else if args[i] == "--" {
            rest.extend(args[i + 1..].iter().cloned());
            break;
        } else if !args[i].starts_with("--") {
            rest.push(args[i].clone());
        } else {
            rest.push(args[i].clone());
        }
        i += 1;
    }
    let path = path.ok_or_else(|| anyhow!("missing {flag}"))?;
    Ok((path, rest))
}

fn ensure_sdk_root() -> Result<()> {
    let root = emulator::android::sdk::default_sdk_root();
    let libc = Path::new(&root).join("system/lib64/libc.so");
    if !libc.exists() {
        return Err(anyhow!(
            "Android {ANDROID_SDK} libc not found at {}\n\
             Pull a device/emulator image first:\n\
               android/sdk36/pull.ps1\n\
             or set BASE_PATH to a tree that contains system/lib64/libc.so",
            libc.display()
        ));
    }
    Ok(())
}
