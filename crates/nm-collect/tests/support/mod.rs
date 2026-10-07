use russh::{
    keys::{Algorithm, PrivateKey},
    server::{self, Msg, Session},
    Channel, ChannelId,
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

pub struct ReplayServer {
    pub address: SocketAddr,
    pub commands: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ReplayServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[derive(Clone)]
struct Replay {
    outputs: Arc<BTreeMap<String, (Vec<u8>, u32)>>,
    commands: Arc<Mutex<Vec<String>>>,
    delay: Duration,
}
impl server::Handler for Replay {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if user == "operator" && password == "test-password" {
            server::Auth::Accept
        } else {
            server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        })
    }
    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.commands.lock().unwrap().push(command.clone());
        session.channel_success(channel)?;
        tokio::time::sleep(self.delay).await;
        let (output, exit) = self
            .outputs
            .get(&command)
            .cloned()
            .unwrap_or_else(|| (b"command not found\n".to_vec(), 127));
        session.data(channel, output)?;
        session.exit_status_request(channel, exit)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
pub fn fixture_outputs() -> BTreeMap<String, (Vec<u8>, u32)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/airos/synthetic-wa-8.7.11");
    [
        ("cat /etc/version", "version.txt"),
        ("cat /etc/board.info", "board-info.txt"),
        ("uptime", "uptime.txt"),
        ("free", "free.txt"),
        ("cat /proc/loadavg", "loadavg.txt"),
        ("mca-status", "mca-status.txt"),
        ("mca-dump", "mca-dump.json"),
        ("wstalist", "wstalist.json"),
        ("iwconfig", "iwconfig.txt"),
        ("ifconfig", "ifconfig.txt"),
        ("cat /proc/net/dev", "proc-net-dev.txt"),
        ("cat /tmp/system.cfg", "system.cfg"),
        ("brctl show", "brctl.txt"),
        ("cat /proc/net/arp", "arp.txt"),
    ]
    .into_iter()
    .map(|(c, f)| (c.into(), (std::fs::read(root.join(f)).unwrap(), 0)))
    .collect()
}
impl ReplayServer {
    pub async fn start(
        key: PrivateKey,
        legacy: bool,
        delay: Duration,
        outputs: BTreeMap<String, (Vec<u8>, u32)>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut preferred = russh::Preferred::DEFAULT;
        if legacy {
            preferred.key = std::borrow::Cow::Owned(vec![Algorithm::Rsa { hash: None }]);
            preferred.kex = std::borrow::Cow::Owned(vec![russh::kex::DH_G1_SHA1]);
            preferred.cipher = std::borrow::Cow::Owned(vec![russh::cipher::AES_128_CBC]);
            preferred.mac = std::borrow::Cow::Owned(vec![russh::mac::HMAC_SHA1]);
        }
        let config = Arc::new(server::Config {
            keys: vec![key],
            preferred,
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let commands = Arc::new(Mutex::new(Vec::new()));
        let replay = Replay {
            outputs: Arc::new(outputs),
            commands: commands.clone(),
            delay,
        };
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                let replay = replay.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, stream, replay).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            address,
            commands,
            task,
        }
    }
}
pub fn key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}
