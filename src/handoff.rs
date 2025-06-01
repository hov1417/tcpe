use crate::base64_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct TcpeHandoffStart {
    pub connection_id: u32,
    #[serde(with = "base64_bytes")]
    pub current_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all="camelCase")]
pub struct TcpeHandoffEnd {
    pub connection_id: u32,
    pub left_over_data: Vec<u8>,
}
