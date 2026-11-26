use super::{Failure, Http, json_object, secret_string};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(super) const KMS: &str = "cloudkms.googleapis.com";

// Reflected CRC32C (Castagnoli), used by the Cloud KMS JSON API.
const CRC32C: [u32; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0x82f63b78 } else { 0 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub(super) fn checksum(data: &[u8]) -> String {
    let crc = data.iter().fold(u32::MAX, |crc, &b| {
        (crc >> 8) ^ CRC32C[((crc as u8) ^ b) as usize]
    });
    (!crc).to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Encrypt<'a> {
    plaintext: &'a str,
    plaintext_crc32c: String,
    additional_authenticated_data: String,
    additional_authenticated_data_crc32c: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Decrypt {
    ciphertext: String,
    ciphertext_crc32c: String,
    additional_authenticated_data: String,
    additional_authenticated_data_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Encrypted {
    name: String,
    ciphertext: String,
    ciphertext_crc32c: String,
    verified_plaintext_crc32c: bool,
    verified_additional_authenticated_data_crc32c: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Decrypted {
    #[serde(deserialize_with = "secret_string")]
    plaintext: Zeroizing<String>,
    plaintext_crc32c: String,
}

pub(super) struct Key<'a> {
    pub http: &'a Http,
    pub key: &'a str,
    pub token: Zeroizing<String>,
}

impl Key<'_> {
    async fn call(
        &self,
        op: &'static str,
        input: &impl Serialize,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        // The only request carrying plaintext wraps a 32-byte key and fixed role AAD.
        let mut body = Zeroizing::new(Vec::with_capacity(512));
        serde_json::to_writer(&mut *body, input).map_err(|_| Failure::new(op))?;
        self.http
            .post(
                op,
                KMS,
                &format!("/v1/{}:{op}", self.key),
                Some(&self.token),
                body,
            )
            .await
    }

    pub(super) async fn decrypt(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, Failure> {
        let bad = Failure::invalid_response("decrypt");
        let response = self
            .call(
                "decrypt",
                &Decrypt {
                    ciphertext: BASE64_STANDARD.encode(ciphertext),
                    ciphertext_crc32c: checksum(ciphertext),
                    additional_authenticated_data: BASE64_STANDARD.encode(aad),
                    additional_authenticated_data_crc32c: checksum(aad),
                },
            )
            .await?;
        let result: Decrypted = json_object(&response).ok_or(bad)?;
        let mut key = Zeroizing::new([0; 32]);
        if BASE64_STANDARD
            .decode_slice(result.plaintext.as_bytes(), key.as_mut())
            .ok()
            != Some(32)
            || checksum(key.as_ref()) != result.plaintext_crc32c
        {
            return Err(bad);
        }
        Ok(key)
    }

    pub(super) async fn encrypt(
        &self,
        plaintext: &[u8; 32],
        aad: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        let bad = Failure::invalid_response("encrypt");
        let encoded = Zeroizing::new(BASE64_STANDARD.encode(plaintext));
        let response = self
            .call(
                "encrypt",
                &Encrypt {
                    plaintext: &encoded,
                    plaintext_crc32c: checksum(plaintext),
                    additional_authenticated_data: BASE64_STANDARD.encode(aad),
                    additional_authenticated_data_crc32c: checksum(aad),
                },
            )
            .await?;
        let result: Encrypted = json_object(&response).ok_or(bad)?;
        let version = result
            .name
            .strip_prefix(self.key)
            .and_then(|s| s.strip_prefix("/cryptoKeyVersions/"))
            .ok_or(bad)?;
        if version.is_empty()
            || !version.bytes().all(|b| b.is_ascii_digit())
            || !result.verified_plaintext_crc32c
            || !result.verified_additional_authenticated_data_crc32c
        {
            return Err(bad);
        }
        let ciphertext = BASE64_STANDARD.decode(result.ciphertext).map_err(|_| bad)?;
        if ciphertext.is_empty() || checksum(&ciphertext) != result.ciphertext_crc32c {
            return Err(bad);
        }
        Ok(ciphertext)
    }
}
