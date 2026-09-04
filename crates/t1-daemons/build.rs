use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");

    let manifest = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let output = PathBuf::from(required_env("OUT_DIR"));
    let compiler = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let archiver = env::var_os("AR").unwrap_or_else(|| "ar".into());
    let archive = output.join("libt1_daemons_native.a");
    let mut objects = Vec::new();

    let sources = vec![
        "t1_xart_listener.c",
        "t1_ncm_ready.c",
        "t1_nss_account.c",
        "t1_service_lifecycle.c",
    ];
    for source_name in sources {
        let source = manifest.join("c").join(source_name);
        let object = output.join(source_name.replace(".c", ".o"));
        compile(&compiler, &source, &object);
        objects.push(object);
    }
    let _ = fs::remove_file(&archive);
    let mut command = Command::new(archiver);
    command.arg("rcs").arg(&archive).args(&objects);
    run(&mut command, "C archive");

    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=t1_daemons_native");
    println!("cargo:rustc-link-lib=systemd");
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
