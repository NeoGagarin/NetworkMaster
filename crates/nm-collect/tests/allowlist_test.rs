use nm_collect::allowlist::all_families;
use regex::Regex;
fn forbidden() -> Regex {
    Regex::new(r"(?i)(\b(set|delete|configure|commit|save|reboot|reset|write|rm|mv|cp|dd|mtd|fwupdate|kill|passwd|useradd)\b|cfgmtd\s+-w|ubnt-|>)").unwrap()
}
#[test]
fn allowlisted_commands_are_read_only() {
    let forbidden = forbidden();
    for (family, commands) in all_families() {
        for command in commands {
            assert!(
                !forbidden.is_match(command.as_str()),
                "mutating {family} command: {}",
                command.as_str()
            );
        }
    }
}
#[test]
fn detector_rejects_mutating_commands() {
    for command in [
        "set system host-name x",
        "DELETE a",
        "configure",
        "commit",
        "save",
        "reboot",
        "reset",
        "write",
        "cfgmtd -w",
        "rm /tmp/x",
        "mv a b",
        "cp a b",
        "echo hi > /tmp/x",
        "dd if=a",
        "mtd",
        "fwupdate",
        "ubnt-upgrade",
        "kill 1",
        "passwd",
        "useradd",
    ] {
        assert!(forbidden().is_match(command), "{command}");
    }
}
