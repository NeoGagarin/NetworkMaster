use crate::SshCommand;
use nm_core::ManagementAddress;
use std::fmt;

#[derive(Clone, Debug, Default)]
pub struct CollectionPlan(pub Vec<PlannedAction>);
#[derive(Clone, Debug)]
pub struct PlannedAction {
    pub transport: Transport,
    pub target: ManagementAddress,
    pub action: Action,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Ssh,
    Http,
    Udp,
    Snmp,
}
#[derive(Clone, Debug)]
pub enum Action {
    SshCommand(SshCommand),
    HttpGet { path: String },
    HttpLogin { endpoint: LoginEndpoint },
    UdpProbe { port: u16 },
    SnmpGet { oids: Vec<String> },
}
/// The only POST endpoints allowed by the future HTTP transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginEndpoint {
    UniFiOs,
    UniFiController,
}
impl LoginEndpoint {
    pub fn path(self) -> &'static str {
        match self {
            Self::UniFiOs => "/api/auth/login",
            Self::UniFiController => "/api/login",
        }
    }
}
impl fmt::Display for CollectionPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return writeln!(f, "No actions planned.");
        }
        for planned in &self.0 {
            write!(f, "{} {:?} ", planned.target, planned.transport)?;
            match &planned.action {
                Action::SshCommand(command) => writeln!(f, "{}", command.as_str())?,
                Action::HttpGet { path } => writeln!(f, "GET {path}")?,
                Action::HttpLogin { endpoint } => {
                    writeln!(f, "POST {} (login only)", endpoint.path())?;
                }
                Action::UdpProbe { port } => writeln!(f, "probe port {port}")?,
                Action::SnmpGet { oids } => writeln!(f, "GET {}", oids.join(", "))?,
            }
        }
        Ok(())
    }
}
