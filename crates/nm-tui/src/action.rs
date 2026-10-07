use crate::app::ScreenId;
use crossterm::event::KeyEvent;
use nm_app::JobEvent;
pub enum Action {
    Key(KeyEvent),
    Tick,
    Job(JobEvent),
    Navigate(ScreenId),
    Quit,
}
pub enum Effect {
    Quit,
    Interrupted,
    SaveSettings,
    StartScan {
        devices: Vec<nm_core::Device>,
        dry_run: bool,
    },
    Discover(nm_collect::net::LocalIface),
    AddCredential {
        profile: nm_core::CredentialProfile,
        secret: nm_app::SecretMaterial,
    },
    ForgetCredential(nm_core::CredentialProfileId),
}
