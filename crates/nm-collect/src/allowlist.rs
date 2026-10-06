//! INVARIANT: every command in this file is read-only. See SPEC §1.3 N1 and §15.2.
//! Adding a command requires: (1) it appears in a const below, (2) the forbidden-verb
//! test passes, (3) a reviewer other than the author approves.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SshCommand(&'static str);
impl SshCommand {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}
// Private constructor, reserved for named M1/M2 constants in this module only.
#[allow(dead_code)]
const fn cmd(s: &'static str) -> SshCommand {
    SshCommand(s)
}
pub mod airos {
    use super::SshCommand;
    pub const ALL: &[SshCommand] = &[];
}
pub mod edgeos {
    use super::SshCommand;
    pub const ALL: &[SshCommand] = &[];
}
pub fn all_families() -> impl Iterator<Item = (&'static str, &'static [SshCommand])> {
    [("airos", airos::ALL), ("edgeos", edgeos::ALL)].into_iter()
}
