use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var_os("CARGO_FEATURE_SERVICE").is_none() {
        return;
    }

    let manifest = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let output = PathBuf::from(required_env("OUT_DIR"));
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let archiver = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let source = manifest.join("c/t1_touchid_cancel.c");
    let object = output.join("t1_touchid_cancel.o");
    let archive = output.join("libt1_touchbar_hw_native.a");

    compile(&compiler, &source, &object);
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("../t1-daemons/c/t1_seqpacket.h").display()
    );
    let _ = fs::remove_file(&archive);
    let mut command = Command::new(archiver);
    command.arg("rcs").arg(&archive).arg(&object);
    run(&mut command, "C archive");

    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=t1_touchbar_hw_native");
}

fn compile(compiler: &OsStr, source: &Path, object: &Path) {
    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        source.with_extension("h").display()
    );
    let mut command = Command::new(compiler);
    command.args([
        OsStr::new("-O2"),
        OsStr::new("-std=c17"),
        OsStr::new("-Wall"),
        OsStr::new("-Wextra"),
        OsStr::new("-Wpedantic"),
        OsStr::new("-Werror"),
        OsStr::new("-fPIC"),
        OsStr::new("-c"),
    ]);
    command.arg(source).arg("-o").arg(object);
    run(&mut command, "C compilation");
}

fn run(command: &mut Command, operation: &str) {
    let status = command
        .status()
        .unwrap_or_else(|_| panic!("{operation} tool could not be started"));
    assert!(status.success(), "{operation} failed");
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("Cargo did not provide {name}"))
}
