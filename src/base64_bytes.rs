use serde::{Deserialize, Serialize};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::de::Deserializer;
use serde::de::Error;
use serde::ser::Serializer;

pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    if s.is_human_readable() {
        STANDARD.encode(v).serialize(s)
    } else {
        v.as_ref().serialize(s)
    }
}

pub fn deserialize<'a, D: Deserializer<'a>>(d: D) -> Result<Vec<u8>, D::Error> {
    if d.is_human_readable() {
        Ok(STANDARD
            .decode(String::deserialize(d)?)
            .map_err(|err| D::Error::custom(format!("invalid base64: {err}")))?)
    } else {
        Ok(Vec::deserialize(d)?)
    }
}
