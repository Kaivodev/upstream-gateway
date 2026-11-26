//! The servicekit sealing file. Field order is also the on-disk encoding.
use super::{LIMIT, json_object};
use crate::Role;
use anyhow::{Result, anyhow, ensure};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

const FORMAT: &str = "kaivo.sealing.v1";
const PURPOSE: &str = "sealing";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct File<T> {
    format: String,
    service: String,
    purpose: String,
    current: i32,
    keys: Vec<T>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    version: i32,
    wrapped: String,
}

fn service(role: Role) -> String {
    format!("upstream-gateway-{}", role.name())
}

pub(super) fn aad(role: Role, version: i32) -> String {
    format!("kaivo:{}:{PURPOSE}:v{version}", service(role))
}

pub(super) fn parse(data: &[u8], role: Role) -> Result<(i32, Vec<u8>)> {
    let invalid = || anyhow!("invalid wrapped key file");
    ensure!(data.len() <= LIMIT, invalid());
    let file: File<&RawValue> = json_object(data).ok_or_else(invalid)?;
    ensure!(file.format == FORMAT, invalid());
    // Exact role and purpose also enforce servicekit's label grammar.
    ensure!(
        file.service == service(role) && file.purpose == PURPOSE,
        "wrapped key file identity mismatch"
    );
    ensure!(
        file.keys.len() == 1,
        "wrapped key file requires exactly one KEK for unversioned records"
    );
    let entry: Entry = json_object(file.keys[0].get().as_bytes()).ok_or_else(invalid)?;
    ensure!(
        entry.version > 0 && file.current == entry.version && !entry.wrapped.is_empty(),
        invalid()
    );
    let ciphertext = BASE64_STANDARD
        .decode(entry.wrapped)
        .map_err(|_| invalid())?;
    Ok((entry.version, ciphertext))
}

pub(super) fn encode(role: Role, version: i32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    ensure!(version > 0 && !ciphertext.is_empty(), "invalid wrapped key");
    let file = File {
        format: FORMAT.into(),
        service: service(role),
        purpose: PURPOSE.into(),
        current: version,
        keys: vec![Entry {
            version,
            wrapped: BASE64_STANDARD.encode(ciphertext),
        }],
    };
    let mut bytes = serde_json::to_vec(&file)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= LIMIT, "wrapped key file too large");
    Ok(bytes)
}
