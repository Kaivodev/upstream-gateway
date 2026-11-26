//! Decoded fields and the original byte range of an EPay query signature.
use anyhow::{Context, Result, ensure};
use kaivo_upstream_sdk::form;
use std::{collections::BTreeMap, ops::Range};

pub struct SignedQuery<'a> {
    raw: &'a [u8],
    pub(super) fields: BTreeMap<Vec<u8>, Vec<u8>>,
    signature: WireValue,
}

struct WireValue {
    range: Range<usize>,
    needs_equals: bool,
}

impl WireValue {
    fn at(offset: usize, pair: &[u8]) -> Self {
        let equals = pair.iter().position(|&b| b == b'=');
        let start = equals.map_or(pair.len(), |i| i + 1);
        Self {
            range: offset + start..offset + pair.len(),
            needs_equals: equals.is_none(),
        }
    }
    fn replace(&self, raw: &[u8], value: &str) -> Vec<u8> {
        let mut result = raw[..self.range.start].to_vec();
        if self.needs_equals {
            result.push(b'=');
        }
        result.extend_from_slice(value.as_bytes());
        result.extend_from_slice(&raw[self.range.end..]);
        result
    }
}

// Mask a signature without canonicalizing the surrounding form bytes.
pub(super) fn mask_form_signature(raw: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    for pair in raw.split(|&b| b == b'&') {
        if form::parse(pair)?.contains_key(b"sign".as_slice()) {
            return Some(WireValue::at(offset, pair).replace(raw, super::MARK));
        }
        offset += pair.len() + 1;
    }
    None
}

impl<'a> SignedQuery<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let mut fields = BTreeMap::new();
        let mut signature = None;
        let mut offset = 0;
        for part in raw.split(|&b| b == b'&') {
            let (key, mut values) = form::parse(part)
                .and_then(|fields| fields.into_iter().next())
                .context("invalid callback query")?;
            ensure!(!key.is_empty(), "empty callback key");
            if key == b"sign" {
                signature = Some(WireValue::at(offset, part));
            }
            ensure!(
                fields.insert(key, values.pop().unwrap()).is_none(),
                "duplicate callback key"
            );
            offset += part.len() + 1;
        }
        Ok(Self {
            raw,
            fields,
            signature: signature.context("missing callback signature")?,
        })
    }

    pub fn signature(&self) -> &[u8] {
        &self.fields[b"sign".as_slice()]
    }

    pub fn replace_signature(&self, replacement: &str) -> Vec<u8> {
        self.signature.replace(self.raw, replacement)
    }
}
