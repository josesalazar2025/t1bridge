use std::process::Command;

#[test]
fn cli_and_environment_opt_in_preserve_authority_failure_without_private_arguments() {
    // Select a command whose authority check fails before any hardware work.
    let denied = if t1_platform::preserved_efi_discovery::is_root() {
        "enroll"
    } else {
        "status"
    };
    for (flag, environment, expected) in
        [(false, "0", false), (true, "0", true), (false, "1", true)]
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_t1bridge"));
        command.env("T1BRIDGE_DIAGNOSTICS", environment);
        if flag {
            command.arg("--diagnostics");
        }
        let result = command.arg(denied).output().unwrap();
        assert_eq!(result.status.code(), Some(3));
        let stderr = String::from_utf8(result.stderr).unwrap();
        assert_eq!(stderr.contains("t1bridge-diagnostic "), expected);
        if expected {
            assert!(stderr.contains("phase=authority result=error code=3"));
        }
    }
    let result = Command::new(env!("CARGO_BIN_EXE_t1bridge"))
        .args(["--diagnostics", "PRIVATE-UNKNOWN-ARGUMENT"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(
        !String::from_utf8(result.stderr)
            .unwrap()
            .contains("PRIVATE")
    );
}
