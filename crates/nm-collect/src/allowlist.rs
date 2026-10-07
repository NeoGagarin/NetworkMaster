//! INVARIANT: every command in this file is read-only. See SPEC §1.3 N1 and §15.2.
//! Adding a command requires: (1) it appears in a const below, (2) the forbidden-verb
//! test passes, (3) a reviewer other than the author approves.

/// Only allowlisted commands can be constructed.
/// ```compile_fail
/// use nm_collect::SshCommand;
/// let command = SshCommand("reboot");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SshCommand(&'static str);
impl SshCommand {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}
// Private constructor, reserved for the named constants in this module only.
const fn cmd(s: &'static str) -> SshCommand {
    SshCommand(s)
}
pub mod airos {
    use super::{cmd, SshCommand};
    pub const VERSION: SshCommand = cmd("cat /etc/version");
    pub const BOARD_INFO: SshCommand = cmd("cat /etc/board.info");
    pub const UPTIME: SshCommand = cmd("uptime");
    pub const FREE: SshCommand = cmd("free");
    pub const LOADAVG: SshCommand = cmd("cat /proc/loadavg");
    pub const MCA_STATUS: SshCommand = cmd("mca-status");
    pub const MCA_DUMP: SshCommand = cmd("mca-dump");
    pub const WSTALIST: SshCommand = cmd("wstalist");
    pub const IWCONFIG: SshCommand = cmd("iwconfig");
    pub const IFCONFIG: SshCommand = cmd("ifconfig");
    pub const NET_DEV: SshCommand = cmd("cat /proc/net/dev");
    pub const SYSTEM_CFG: SshCommand = cmd("cat /tmp/system.cfg");
    pub const BRCTL: SshCommand = cmd("brctl show");
    pub const ARP: SshCommand = cmd("cat /proc/net/arp");
    pub const ALL: &[SshCommand] = &[
        VERSION, BOARD_INFO, UPTIME, FREE, LOADAVG, MCA_STATUS, MCA_DUMP, WSTALIST, IWCONFIG,
        IFCONFIG, NET_DEV, SYSTEM_CFG, BRCTL, ARP,
    ];
}
pub mod edgeos {
    use super::{cmd, SshCommand};
    pub const CONFIG_CMDS: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands");
    pub const VERSION: SshCommand = cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show version");
    pub const INTERFACES: SshCommand = cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces");
    pub const IF_ETH_DETAIL: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces ethernet detail");
    pub const ROUTE_SUMMARY: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route summary");
    pub const ROUTE: SshCommand = cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip route");
    pub const OSPF_NEIGHBOR: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip ospf neighbor");
    pub const OSPF_INTERFACE: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip ospf interface");
    pub const BGP_SUMMARY: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ip bgp summary");
    pub const OFFLOAD: SshCommand = cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show ubnt offload");
    pub const DHCP_LEASES: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp leases");
    pub const DHCP_STATS: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show dhcp statistics");
    pub const FW_STATS: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show firewall statistics");
    pub const NAT_STATS: SshCommand =
        cmd("/opt/vyatta/bin/vyatta-op-cmd-wrapper show nat statistics");
    pub const UPTIME: SshCommand = cmd("uptime");
    pub const LOADAVG: SshCommand = cmd("cat /proc/loadavg");
    pub const MEMINFO: SshCommand = cmd("cat /proc/meminfo");
    pub const NET_DEV: SshCommand = cmd("cat /proc/net/dev");
    pub const ARP: SshCommand = cmd("cat /proc/net/arp");
    pub const ALL: &[SshCommand] = &[
        CONFIG_CMDS,
        VERSION,
        INTERFACES,
        IF_ETH_DETAIL,
        ROUTE_SUMMARY,
        ROUTE,
        OSPF_NEIGHBOR,
        OSPF_INTERFACE,
        BGP_SUMMARY,
        OFFLOAD,
        DHCP_LEASES,
        DHCP_STATS,
        FW_STATS,
        NAT_STATS,
        UPTIME,
        LOADAVG,
        MEMINFO,
        NET_DEV,
        ARP,
    ];
}
pub fn all_families() -> impl Iterator<Item = (&'static str, &'static [SshCommand])> {
    [("airos", airos::ALL), ("edgeos", edgeos::ALL)].into_iter()
}
