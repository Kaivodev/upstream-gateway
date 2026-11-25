//! Write-time keyed fingerprints let routing detect reflected input without
//! opening a credential envelope or interpreting a credential as a key.
use base64::prelude::*;
use ring::hmac;
use std::collections::{BTreeMap, BTreeSet};
use tonic::Status;
use upstream_host::package::hex;
use zeroize::Zeroizing;

const PREFIX: usize = 16;
pub(crate) struct Fingerprints(hmac::Key);
impl Fingerprints {
    pub fn new(key: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, key))
    }
    fn tag(&self, b: &[u8]) -> [u8; 32] {
        hmac::sign(&self.0, b).as_ref().try_into().unwrap()
    }
    pub fn describe(&self, values: &BTreeMap<String, Zeroizing<String>>) -> Vec<Vec<u8>> {
        let mut tags = BTreeSet::new();
        for value in values.values() {
            let value = value.as_bytes();
            let mut add = |b: &[u8]| {
                let mut entry = (b.len() as u32).to_be_bytes().to_vec();
                entry.extend(self.tag(&b[..b.len().min(PREFIX)]));
                entry.extend(self.tag(b));
                tags.insert(entry);
            };
            add(value);
            for text in [
                hex(value),
                hex(value).to_uppercase(),
                BASE64_STANDARD.encode(value),
                BASE64_STANDARD_NO_PAD.encode(value),
                BASE64_URL_SAFE.encode(value),
                BASE64_URL_SAFE_NO_PAD.encode(value),
            ] {
                add(Zeroizing::new(text).as_bytes())
            }
        }
        tags.into_iter().collect()
    }
    pub fn contains(
        &self,
        markers: &[Vec<u8>],
        payload: &crate::api::CallbackPayload,
        config: &BTreeMap<String, String>,
    ) -> Result<bool, Status> {
        let mut index = BTreeMap::<usize, BTreeMap<&[u8], Vec<(usize, &[u8])>>>::new();
        for m in markers {
            if m.len() != 68 {
                return Err(Status::data_loss("invalid credential metadata"));
            }
            let len = u32::from_be_bytes(m[..4].try_into().unwrap()) as usize;
            if len == 0 {
                return Err(Status::data_loss("invalid credential metadata"));
            }
            index
                .entry(len.min(PREFIX))
                .or_default()
                .entry(&m[4..36])
                .or_default()
                .push((len, &m[36..]));
        }
        let matches = |data: &[u8]| {
            for (width, lookup) in &index {
                for (pos, chunk) in data.windows(*width).enumerate() {
                    let tag = self.tag(chunk);
                    if let Some(candidates) = lookup.get(tag.as_slice()) {
                        for &(len, expected) in candidates {
                            if let Some(full) = data[pos..].get(..len)
                                && self.tag(full) == expected
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        };
        let mut fields = vec![
            payload.method.as_bytes(),
            payload.raw_query.as_slice(),
            payload.body.as_slice(),
        ];
        if let Some(ip) = &payload.source_ip {
            fields.push(ip.as_bytes());
        }
        for h in &payload.headers {
            fields.push(h.name.as_bytes());
            fields.extend(h.values.iter().map(String::as_bytes));
        }
        fields.extend(config.values().map(String::as_bytes));
        Ok(fields.into_iter().any(|field| {
            matches(field) || upstream_host::json::escaped_strings_match(field, matches)
        }))
    }
}
