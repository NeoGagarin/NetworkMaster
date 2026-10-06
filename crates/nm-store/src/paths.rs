use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    resolve(
        std::env::var_os("NETMASTER_DATA_DIR"),
        dirs::data_local_dir(),
    )
}
fn resolve(override_dir: Option<std::ffi::OsString>, local: Option<PathBuf>) -> PathBuf {
    if let Some(path) = override_dir.filter(|p| !p.is_empty()) {
        return PathBuf::from(path);
    }
    local
        .unwrap_or_else(|| PathBuf::from("."))
        .join(if cfg!(windows) {
            "NetworkMaster"
        } else {
            "networkmaster"
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn override_wins() {
        assert_eq!(
            resolve(Some("override".into()), Some("default".into())),
            PathBuf::from("override")
        );
    }
}
