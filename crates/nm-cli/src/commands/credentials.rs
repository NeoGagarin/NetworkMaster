use crate::{
    cli::{CredsAdd, Kind},
    commands::not_implemented,
};
use nm_app::{AppService, SecretMaterial, SecretString, SecretVec};
use nm_core::{CredentialKind, CredentialProfile, CredentialProfileId, StorageMode};
use std::io::{self, BufRead, Read};
use zeroize::Zeroizing;

async fn read_secret(stdin: bool, prompt: &'static str) -> anyhow::Result<SecretString> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<SecretString> {
        let secret = if stdin {
            let mut value = Zeroizing::new(String::new());
            let bytes = io::stdin().lock().take(1_048_577).read_line(&mut value)?;
            anyhow::ensure!(bytes <= 1_048_576, "secret exceeds input limit");
            anyhow::ensure!(bytes > 0, "no secret on stdin");
            if value.ends_with('\n') {
                value.pop();
                if value.ends_with('\r') {
                    value.pop();
                }
            }
            SecretString::new(std::mem::take(&mut *value))
        } else {
            SecretString::new(rpassword::prompt_password(prompt)?)
        };
        Ok(secret)
    })
    .await?
}
pub async fn add(args: &CredsAdd, json: bool, svc: &AppService) -> anyhow::Result<u8> {
    if args.persist {
        return Ok(not_implemented("M5", json));
    }
    let username = || -> anyhow::Result<String> {
        args.username
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("--username is required for this credential kind"))
    };
    // Validate non-secret parameters before prompting.
    let kind = match args.kind {
        Kind::SshPassword => CredentialKind::SshPassword {
            username: username()?,
        },
        Kind::SshKey => {
            anyhow::ensure!(
                args.key_file.is_some(),
                "--key-file is required for ssh-key"
            );
            CredentialKind::SshKey {
                username: username()?,
                has_passphrase: args.has_passphrase,
            }
        }
        Kind::ApiToken => CredentialKind::ApiToken,
        Kind::HttpBasic => CredentialKind::HttpBasic {
            username: username()?,
        },
        Kind::SnmpV2c => CredentialKind::SnmpV2c,
        Kind::SnmpV3 => CredentialKind::SnmpV3 {
            username: username()?,
            auth_proto: args.auth_proto.clone(),
            priv_proto: args.priv_proto.clone(),
        },
    };
    let secret = match args.kind {
        Kind::SshKey => {
            let key = SecretVec::new(std::fs::read(
                args.key_file.as_ref().expect("validated key file"),
            )?);
            let passphrase = if args.has_passphrase {
                Some(read_secret(args.secret_from_stdin, "Key passphrase: ").await?)
            } else {
                None
            };
            SecretMaterial::SshKey { key, passphrase }
        }
        Kind::SshPassword => SecretMaterial::SshPassword(
            read_secret(args.secret_from_stdin, "SSH password: ").await?,
        ),
        Kind::ApiToken => {
            SecretMaterial::ApiToken(read_secret(args.secret_from_stdin, "API token: ").await?)
        }
        Kind::HttpBasic => {
            SecretMaterial::HttpBasic(read_secret(args.secret_from_stdin, "HTTP password: ").await?)
        }
        Kind::SnmpV2c => {
            SecretMaterial::SnmpV2c(read_secret(args.secret_from_stdin, "SNMP community: ").await?)
        }
        Kind::SnmpV3 => {
            anyhow::ensure!(
                !args.secret_from_stdin,
                "SNMPv3 requires two interactive prompts in M0"
            );
            SecretMaterial::SnmpV3 {
                auth: read_secret(false, "SNMP authentication secret: ").await?,
                privacy: Some(read_secret(false, "SNMP privacy secret: ").await?),
            }
        }
    };
    let profile = CredentialProfile {
        id: CredentialProfileId::new(),
        name: args.name.clone(),
        kind,
        storage: StorageMode::SessionOnly,
        scope_hint: args.scope_hint.clone(),
    };
    svc.add_credential(&profile, secret).await?;
    if json {
        println!("{}", serde_json::to_string(&profile)?);
    } else {
        println!(
            "{} {} (session-only; secret is forgotten when this process exits)",
            profile.id, profile.name
        );
    }
    Ok(0)
}
