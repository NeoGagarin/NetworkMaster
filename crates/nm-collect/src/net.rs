use crate::TargetGate;
use async_trait::async_trait;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Debug)]
pub struct LocalIface {
    pub name: String,
    pub ipv4: std::net::Ipv4Addr,
    pub broadcast: std::net::Ipv4Addr,
    pub netmask: std::net::Ipv4Addr,
}
pub fn list_local_interfaces() -> io::Result<Vec<LocalIface>> {
    let mut result = Vec::new();
    for iface in if_addrs::get_if_addrs()? {
        if iface.is_loopback() {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            if let Some(broadcast) = v4.broadcast {
                result.push(LocalIface {
                    name: iface.name,
                    ipv4: v4.ip,
                    broadcast,
                    netmask: v4.netmask,
                });
            }
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name).then(a.ipv4.cmp(&b.ipv4)));
    Ok(result)
}

#[async_trait]
pub trait NetFactory: Send + Sync {
    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream>;
    async fn udp_bind(&self, bind: SocketAddr) -> io::Result<UdpSocket>;
}
pub struct RealNet {
    gate: Arc<TargetGate>,
}
impl RealNet {
    pub fn new(gate: Arc<TargetGate>) -> Self {
        Self { gate }
    }
}
#[async_trait]
impl NetFactory for RealNet {
    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.gate
            .check_address(addr)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        TcpStream::connect(addr).await
    }
    async fn udp_bind(&self, bind: SocketAddr) -> io::Result<UdpSocket> {
        if !bind.ip().is_unspecified()
            && !if_addrs::get_if_addrs()?
                .iter()
                .any(|interface| interface.ip() == bind.ip())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP bind must use a local interface",
            ));
        }
        // Enumeration enforces local ownership even if the OS permits nonlocal
        // binds. Binding emits no packets. M1 owns the L2 broadcast policy.
        UdpSocket::bind(bind).await
    }
}
#[derive(Default)]
pub struct DenyAllNet;
#[async_trait]
impl NetFactory for DenyAllNet {
    async fn tcp_connect(&self, _: SocketAddr) -> io::Result<TcpStream> {
        Err(denied())
    }
    async fn udp_bind(&self, _: SocketAddr) -> io::Result<UdpSocket> {
        Err(denied())
    }
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "network disabled")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_before_connecting() {
        // An actual listening socket proves refusal is policy, not connection failure.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let net = RealNet::new(Arc::new(TargetGate::default()));
        assert_eq!(
            net.tcp_connect(listener.local_addr().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn deny_all_refuses_both_socket_types() {
        let addr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(
            DenyAllNet.tcp_connect(addr).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            DenyAllNet.udp_bind(addr).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[tokio::test]
    async fn udp_binding_requires_a_local_interface() {
        let net = RealNet::new(Arc::new(TargetGate::default()));
        let socket = net.udp_bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert!(socket.local_addr().unwrap().ip().is_loopback());
        assert_eq!(
            net.udp_bind("255.255.255.255:0".parse().unwrap())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
