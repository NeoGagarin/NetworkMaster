fn requires_serialize<T: serde::Serialize>(_: &T) {}
fn main() {
    requires_serialize(&nm_creds::CredArena::new());
}
