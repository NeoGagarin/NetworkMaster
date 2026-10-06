use assert_cmd::Command;
use predicates::prelude::*;
fn command(dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("netmaster"));
    cmd.env("NETMASTER_DATA_DIR", dir)
        .env("NETMASTER_NET", "deny");
    cmd
}
#[test]
fn inventory_add_list_enroll_and_data_dir_override() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args([
            "inventory",
            "add",
            "192.0.2.10",
            "--family",
            "airos",
            "--name",
            "test",
        ])
        .assert()
        .success();
    assert!(dir.path().join("netmaster.db").exists());
    let list = command(dir.path())
        .args(["inventory", "list", "--json"])
        .output()
        .unwrap();
    let devices: Vec<nm_core::Device> = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(devices.len(), 1);
    assert!(!devices[0].enrolled);
    command(dir.path())
        .args(["inventory", "enroll", &devices[0].id.to_string()])
        .assert()
        .success();
    let list = command(dir.path())
        .args(["inventory", "list", "--json"])
        .output()
        .unwrap();
    let devices: Vec<nm_core::Device> = serde_json::from_slice(&list.stdout).unwrap();
    assert!(devices[0].enrolled);
    command(dir.path())
        .args(["inventory", "enroll", "--all-candidates"])
        .assert()
        .code(3);
}
#[test]
fn credential_creation_is_audited_without_storing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "planted-super-secret-731";
    command(dir.path())
        .args([
            "creds",
            "add",
            "fleet",
            "--kind",
            "ssh-password",
            "--username",
            "readonly",
            "--secret-from-stdin",
            "--json",
        ])
        .write_stdin(format!("{secret}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains(secret).not());
    let audit = command(dir.path())
        .args(["audit", "tail", "--json"])
        .output()
        .unwrap();
    let events: Vec<nm_core::AuditEvent> = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(events[0].action, nm_core::AuditAction::CredentialCreated);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }
    command(dir.path())
        .args(["forget", "--all-credentials"])
        .assert()
        .success();
    command(dir.path())
        .args(["audit", "tail", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CredentialForgotten"));
}
#[test]
fn stubs_and_usage_have_stable_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    command(dir.path())
        .args(["scan", "--dry-run"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("planned for M1"));
    command(dir.path())
        .args(["creds", "add", "fleet", "--persist"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("planned for M5"));
    command(dir.path())
        .args(["inventory", "enroll"])
        .assert()
        .code(2);
    command(dir.path())
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.0.1"));
}
#[test]
fn explicit_data_dir_wins_over_environment() {
    let env = tempfile::tempdir().unwrap();
    let flag = tempfile::tempdir().unwrap();
    command(env.path())
        .arg("--data-dir")
        .arg(flag.path())
        .args(["inventory", "list", "--json"])
        .assert()
        .success()
        .stdout("[]\n");
    assert!(flag.path().join("netmaster.db").exists());
    assert!(!env.path().join("netmaster.db").exists());
}
