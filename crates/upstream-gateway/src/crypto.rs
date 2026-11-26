use crate::{
    Mode, Role,
    encoding::{Encoder, hash},
    wire::invalid,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::{
    collections::BTreeMap, fs::File, io::Read, os::unix::fs::PermissionsExt, path::Path, sync::Arc,
};
use tonic::Status;
use zeroize::Zeroizing;

/// Adapters must authenticate the supplied context and bound each call.
pub trait Kms: Send + Sync {
    fn wrap(&self, dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, Status>;
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Status>;
    fn development_only(&self) -> bool {
        false
    }
}
pub struct LocalKms {
    key: Zeroizing<[u8; 32]>,
    development_only: bool,
}
impl LocalKms {
    pub fn from_file(mode: Mode, path: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(mode, Mode::Development { .. }),
            "local KMS requires development mode"
        );
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.is_file() && meta.permissions().mode() & 0o177 == 0 && meta.len() == 32,
            "invalid KEK file"
        );
        let mut key = Zeroizing::new([0; 32]);
        file.read_exact(key.as_mut())?;
        Ok(Self {
            key,
            development_only: true,
        })
    }
    pub(crate) fn from_cloud_kms(key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            key,
            development_only: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn ephemeral() -> Self {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::fill(key.as_mut()).unwrap();
        Self {
            key,
            development_only: true,
        }
    }
}
fn damaged() -> Status {
    Status::data_loss("sealed record failed authentication")
}
fn encrypt(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Status> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| damaged())?);
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|_| Status::unavailable("entropy unavailable"))?;
    let mut out = nonce.to_vec();
    out.extend(data);
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut out[12..],
        )
        .map_err(|_| damaged())?;
    out.extend(tag.as_ref());
    Ok(out)
}
fn decrypt(key: &[u8], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Status> {
    let (nonce, cipher) = data.split_at_checked(12).ok_or_else(damaged)?;
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| damaged())?);
    let mut out = Zeroizing::new(cipher.to_vec());
    let len = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| damaged())?,
            Aad::from(aad),
            &mut out,
        )
        .map_err(|_| damaged())?
        .len();
    out.truncate(len);
    Ok(out)
}
impl Kms for LocalKms {
    fn wrap(&self, dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, Status> {
        encrypt(self.key.as_ref(), dek, aad)
    }
    fn unwrap(&self, data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Status> {
        decrypt(self.key.as_ref(), data, aad)
    }
    fn development_only(&self) -> bool {
        self.development_only
    }
}
#[derive(Clone)]
pub(crate) struct Vault(pub Arc<dyn Kms>);
impl Vault {
    pub fn seal(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Status> {
        let mut dek = Zeroizing::new([0; 32]);
        getrandom::fill(dek.as_mut()).map_err(|_| Status::unavailable("entropy unavailable"))?;
        let mut out = Encoder::default();
        out.bytes(&self.0.wrap(dek.as_ref(), aad)?);
        out.0.extend(encrypt(dek.as_ref(), data, aad)?);
        Ok(out.0)
    }
    pub fn open(&self, data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Status> {
        let (len, rest) = data.split_at_checked(4).ok_or_else(damaged)?;
        let (wrapped, cipher) = rest
            .split_at_checked(u32::from_be_bytes(len.try_into().unwrap()) as usize)
            .ok_or_else(damaged)?;
        let dek = self.0.unwrap(wrapped, aad)?;
        decrypt(&dek, cipher, aad)
    }
}
pub(crate) fn aad(domain: &str, role: Role, fields: &[&str]) -> Vec<u8> {
    let mut e = Encoder::default();
    e.string(domain);
    e.string(role.name());
    for s in fields {
        e.string(s)
    }
    e.0
}
pub(crate) struct Credentials {
    pub canonical: Zeroizing<Vec<u8>>,
    pub digest: Vec<u8>,
    pub values: BTreeMap<String, Zeroizing<String>>,
}
pub(crate) fn strings(input: &[u8]) -> Result<BTreeMap<String, String>, Status> {
    if input.is_empty() || input.len() > 65536 {
        return Err(invalid());
    }
    stored_strings(input)
}

/// Canonical control-character escapes can be longer than the admitted input.
pub(crate) fn stored_strings(input: &[u8]) -> Result<BTreeMap<String, String>, Status> {
    let value = upstream_host::json::object(input).map_err(|_| invalid())?;
    serde_json::from_value(value).map_err(|_| invalid())
}
pub(crate) fn credentials(input: &[u8]) -> Result<Credentials, Status> {
    let map = strings(input)?;
    if !(1..=64).contains(&map.len())
        || map.iter().any(|(k, v)| {
            k.len() > 64
                || !k.starts_with(|c: char| c.is_ascii_lowercase())
                || !k
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                || v.is_empty()
                || v.contains('\0')
        })
    {
        return Err(invalid());
    }
    // This format is signed by both owners and evolves independently of manifests.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut canonical = Zeroizing::new(vec![b'{']);
    for (i, (name, value)) in map.iter().enumerate() {
        if i > 0 {
            canonical.push(b',')
        }
        canonical.push(b'"');
        canonical.extend(name.bytes());
        canonical.extend(b"\":\"");
        for b in value.bytes() {
            match b {
                b'"' | b'\\' => canonical.extend([b'\\', b]),
                0..=31 => {
                    canonical.extend(b"\\u00");
                    canonical.extend([HEX[(b / 16) as usize], HEX[(b % 16) as usize]])
                }
                _ => canonical.push(b),
            }
        }
        canonical.push(b'"')
    }
    canonical.push(b'}');
    Ok(Credentials {
        digest: hash(&canonical),
        canonical,
        values: map
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect(),
    })
}
