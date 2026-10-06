pub mod audit;
pub mod devices;
pub mod profiles;
pub mod settings;
pub mod sites;
pub mod snapshots;
pub use audit::AuditRepo;
pub use devices::{DeviceFilter, DeviceRepo};
pub use profiles::ProfileRepo;
pub use settings::SettingsRepo;
pub use sites::SiteRepo;
pub use snapshots::SnapshotRepo;

fn json<T: serde::Serialize>(value: &T) -> crate::Result<String> {
    Ok(serde_json::to_string(value)?)
}
// rusqlite rows yield owned strings; these helpers consume that row value.
#[allow(clippy::needless_pass_by_value)]
fn from_json<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}
#[allow(clippy::needless_pass_by_value)]
fn id<T: std::str::FromStr>(value: String) -> rusqlite::Result<T>
where
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{e}"),
            )),
        )
    })
}
