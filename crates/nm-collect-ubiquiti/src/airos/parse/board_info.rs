use super::{key_values, ParseError};
use serde::Serialize;
#[derive(Debug, Serialize)]
pub struct BoardInfo {
    pub sysid: Option<String>,
    pub name: Option<String>,
    pub shortname: Option<String>,
    pub hwaddr: Option<String>,
    pub subtype: Option<String>,
}
pub fn parse(bytes: &[u8]) -> Result<BoardInfo, ParseError> {
    let v = key_values(bytes)?;
    Ok(BoardInfo {
        sysid: v.get("board.sysid").cloned(),
        name: v.get("board.name").cloned(),
        shortname: v.get("board.shortname").cloned(),
        hwaddr: v.get("board.hwaddr").cloned(),
        subtype: v.get("board.subtype").cloned(),
    })
}
