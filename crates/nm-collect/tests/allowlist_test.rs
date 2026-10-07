//! INVARIANT N1: every allowlisted SSH command is read-only (SPEC §1.3, §15.2).
//!
//! The `SshCommand` private constructor is the first guard. This test is the second:
//! it rejects mutating verbs, privilege escalation, interpreters, and every shell
//! metacharacter that could chain a second command onto an innocent-looking first one.
use nm_collect::allowlist::all_families;
use regex::Regex;

fn forbidden() -> Regex {
    Regex::new(concat!(
        r"(?i)(",
        // Shell metacharacters: command chaining, pipes, substitution, redirection.
        r"[;|&`$()<>]",
        // Mutating verbs and tools, as whole words.
        r"|\b(set|delete|configure|commit|save|reboot|reset|write|rm|mv|cp|dd|mtd|cfgmtd",
        r"|fwupdate|kill|passwd|useradd|sudo|su|sh|bash|vbash|tee|touch|sed|chmod|chown",
        r"|mount|umount|echo|printf)\b",
        // Vendor maintenance utilities.
        r"|ubnt-",
        r")",
    ))
    .unwrap()
}

#[test]
fn invariant_n1_no_mutating_verbs_in_allowlist() {
    let forbidden = forbidden();
    for (family, commands) in all_families() {
        assert!(!commands.is_empty(), "{family} allowlist is empty");
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
        "cfgmtd -r",
        "rm /tmp/x",
        "mv a b",
        "cp a b",
        "echo hi > /tmp/x",
        "echo hi",
        "dd if=a",
        "mtd",
        "fwupdate",
        "ubnt-upgrade",
        "kill 1",
        "passwd",
        "useradd",
        // Chaining and escalation around an otherwise read-only command.
        "cat /etc/version; reboot",
        "mca-status | sh",
        "cat /tmp/x && touch /tmp/y",
        "cat /tmp/x || reboot",
        "cat $(id)",
        "cat `id`",
        "sudo cat /tmp/x",
        "su -c id",
        "sh -c id",
        "bash -c id",
        "vbash -ic 'configure'",
        "tee /tmp/x",
        "touch /tmp/x",
        "sed -i s/a/b/ /tmp/x",
        "chmod 777 /tmp/x",
        "chown root /tmp/x",
        "mount -o remount,rw /",
        "cat < /tmp/x",
    ] {
        assert!(forbidden().is_match(command), "not rejected: {command}");
    }
}

#[test]
fn detector_accepts_read_only_shapes() {
    // Guard against the regex growing so broad that legitimate commands trip it.
    for command in [
        "cat /etc/version",
        "cat /proc/net/dev",
        "brctl show",
        "mca-status",
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands",
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route summary",
        "/opt/vyatta/bin/vyatta-op-cmd-wrapper show ubnt offload",
    ] {
        assert!(
            !forbidden().is_match(command),
            "wrongly rejected: {command}"
        );
    }
}
