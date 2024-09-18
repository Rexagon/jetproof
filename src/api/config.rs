use std::net::SocketAddr;
use std::path::PathBuf;

use bytesize::ByteSize;
use everscale_types::boc::Boc;
use everscale_types::cell::Cell;
use everscale_types::models::StdAddr;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub master_addr: StdAddr,
    pub storage_path: PathBuf,
    #[serde(default = "default_storage_cache")]
    pub storage_cache: ByteSize,
    #[serde(deserialize_with = "hex_or_base64_cell")]
    pub wallet_code: Cell,
}

fn default_storage_cache() -> ByteSize {
    ByteSize::gib(1)
}

fn hex_or_base64_cell<'de, D>(deserializer: D) -> Result<Cell, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(deserializer)?;
    if s.starts_with("b5ee") {
        let bytes = hex::decode(s).map_err(Error::custom)?;
        Boc::decode(bytes).map_err(Error::custom)
    } else {
        Boc::decode_base64(s).map_err(Error::custom)
    }
}
