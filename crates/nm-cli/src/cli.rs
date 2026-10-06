use clap::{Args, Parser, Subcommand, ValueEnum};
use nm_core::{CredentialProfileId, DeviceFamily, DeviceId, ManagementAddress, SnapshotId};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "netmaster",
    version,
    about = "Read-only network assessment (pre-alpha)"
)]
pub struct Cli {
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub ascii: bool,
    #[arg(long, global = true)]
    pub no_color: bool,
    #[arg(short='v',global=true,action=clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Option<Command>,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    Inventory {
        #[command(subcommand)]
        command: Inventory,
    },
    Creds {
        #[command(subcommand)]
        command: Creds,
    },
    Scan {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        concurrency: Option<usize>,
    },
    Analyze {
        #[arg(long)]
        snapshot: Option<SnapshotId>,
    },
    Findings {
        #[arg(long,value_parser=["info","low","medium","high","critical"])]
        severity: Option<String>,
    },
    Diff {
        snapshot_a: SnapshotId,
        snapshot_b: SnapshotId,
    },
    Report {
        #[arg(long)]
        snapshot: SnapshotId,
        #[arg(long)]
        out: PathBuf,
    },
    Ai {
        #[command(subcommand)]
        command: Ai,
    },
    Export {
        #[arg(long)]
        snapshot: SnapshotId,
        #[arg(long)]
        out: PathBuf,
    },
    Mcp {
        #[command(subcommand)]
        command: Mcp,
    },
    Audit {
        #[command(subcommand)]
        command: Audit,
    },
    Fixture {
        #[command(subcommand)]
        command: Fixture,
    },
    Forget {
        #[arg(long, required = true)]
        all_credentials: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum Inventory {
    Add {
        addr: ManagementAddress,
        #[arg(long, default_value = "unknown")]
        family: DeviceFamily,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    #[command(group(clap::ArgGroup::new("source").required(true).args(["file", "uisp", "unifi"])))]
    Import(ImportArgs),
    Discover {
        #[arg(long)]
        interface: String,
    },
    List,
    Enroll {
        #[arg(
            required_unless_present = "all_candidates",
            conflicts_with = "all_candidates"
        )]
        ids: Vec<DeviceId>,
        #[arg(long)]
        all_candidates: bool,
    },
}
#[derive(Debug, Args)]
#[group(skip)]
pub struct ImportArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub uisp: Option<String>,
    #[arg(long)]
    pub unifi: Option<String>,
    #[arg(long)]
    pub token_from_stdin: bool,
    #[arg(long)]
    pub site: Option<String>,
}
#[derive(Debug, Subcommand)]
pub enum Creds {
    Add(CredsAdd),
    Assign {
        profile: CredentialProfileId,
        #[arg(long,num_args=1..,required_unless_present_any=["site","family"],conflicts_with_all=["site","family"])]
        devices: Vec<DeviceId>,
        #[arg(long, conflicts_with = "family")]
        site: Option<String>,
        #[arg(long)]
        family: Option<DeviceFamily>,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Kind {
    SshPassword,
    SshKey,
    ApiToken,
    HttpBasic,
    SnmpV2c,
    SnmpV3,
}
#[derive(Debug, Args)]
pub struct CredsAdd {
    pub name: String,
    #[arg(long, value_enum, default_value = "ssh-password")]
    pub kind: Kind,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub persist: bool,
    #[arg(long)]
    pub secret_from_stdin: bool,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub has_passphrase: bool,
    #[arg(long, default_value = "")]
    pub scope_hint: String,
    #[arg(long, default_value = "sha256")]
    pub auth_proto: String,
    #[arg(long, default_value = "aes")]
    pub priv_proto: String,
}
#[derive(Debug, Subcommand)]
pub enum Ai {
    Run {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        model: String,
        #[arg(long,value_parser=["full","names","none"],default_value="full")]
        redact: String,
        #[arg(long)]
        teach: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Debug, Subcommand)]
pub enum Mcp {
    Serve {
        #[arg(long)]
        snapshot: Option<SnapshotId>,
        #[arg(long)]
        no_redact: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum Audit {
    Tail {
        #[arg(short = 'n', default_value_t = 100)]
        count: usize,
    },
}
#[derive(Debug, Subcommand)]
pub enum Fixture {
    Capture {
        #[arg(long)]
        device: DeviceId,
        #[arg(long)]
        out: PathBuf,
    },
}

// Keep parsing tested independently of opening a database or starting a runtime.
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }
    #[test]
    fn enrollment_is_explicit() {
        assert!(Cli::try_parse_from(["netmaster", "inventory", "enroll"]).is_err());
        assert!(
            Cli::try_parse_from(["netmaster", "inventory", "enroll", "--all-candidates"]).is_ok()
        );
    }
    #[test]
    fn import_sources_accept_their_authentication_options() {
        for args in [
            vec!["netmaster", "inventory", "import", "--file", "devices.csv"],
            vec![
                "netmaster",
                "inventory",
                "import",
                "--uisp",
                "https://uisp.example",
                "--token-from-stdin",
            ],
            vec![
                "netmaster",
                "inventory",
                "import",
                "--unifi",
                "https://controller",
                "--token-from-stdin",
                "--site",
                "default",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        assert!(
            Cli::try_parse_from(["netmaster", "inventory", "import", "--token-from-stdin"])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "netmaster",
            "inventory",
            "import",
            "--file",
            "devices.csv",
            "--uisp",
            "https://uisp.example"
        ])
        .is_err());
    }
}
