//! Decoded fields and the original byte range of an EPay query signature.
use anyhow::{Context, Result, ensure};
use kaivo_upstream_sdk::form;
use std::{collections::BTreeMap, ops::Range};

pub struct SignedQuery<'a> {
    raw: &'a [u8],
    pub(super) fields: BTreeMap<Vec<u8>, Vec<u8>>,
    signature: Range<usize>,
    needs_equals: bool,
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
                let equals = part.iter().position(|&b| b == b'=');
                let start = equals.map_or(part.len(), |n| n + 1);
                signature = Some((offset + start..offset + part.len(), equals.is_none()));
            }
            ensure!(
                fields.insert(key, values.pop().unwrap()).is_none(),
                "duplicate callback key"
            );
            offset += part.len() + 1;
        }
        let (signature, needs_equals) = signature.context("missing callback signature")?;
        Ok(Self {
            raw,
            fields,
            signature,
            needs_equals,
        })
    }

    pub fn signature(&self) -> &[u8] {
        &self.fields[b"sign".as_slice()]
    }

    pub fn replace_signature(&self, replacement: &str) -> Vec<u8> {
        let mut query = self.raw[..self.signature.start].to_vec();
        if self.needs_equals {
            query.push(b'=');
        }
        query.extend_from_slice(replacement.as_bytes());
        query.extend_from_slice(&self.raw[self.signature.end..]);
        query
    }
}
