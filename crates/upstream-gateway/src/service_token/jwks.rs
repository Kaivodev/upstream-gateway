use super::{INVALID_KEYS, decode};
use anyhow::{Result, anyhow};
use num_bigint::BigUint;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, sync::LazyLock};

pub(super) type KeySet = BTreeMap<String, Key>;

pub(super) enum Key {
    Rsa(RsaPublicKeyComponents<Vec<u8>>),
    Ec(Vec<u8>),
}
impl Key {
    pub fn signed(&self, alg: &str, message: &[u8], signature: &[u8]) -> bool {
        match (self, alg) {
            (Self::Ec(point), "ES256") => {
                signature.len() == 64
                    && UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                        .verify(message, signature)
                        .is_ok()
            }
            (Self::Rsa(key), "RS256") => key
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            _ => false,
        }
    }
}

// Go decodes JWK structs in input order with case-insensitive field names,
// while the private-member check uses an exact, case-sensitive map lookup.
struct Members<'a>(Vec<(String, &'a RawValue)>);
impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'a> Visitor<'a> for Fields {
            type Value = Members<'a>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'a>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(Members(fields))
            }
        }
        d.deserialize_map(Fields)
    }
}

fn field_name(name: &str) -> String {
    // These are the two non-ASCII Unicode simple folds equivalent to ASCII.
    name.to_ascii_lowercase()
        .replace('K', "k")
        .replace('ſ', "s")
}

fn unsigned(text: &str) -> Option<Vec<u8>> {
    let bytes = decode(text)?;
    let start = bytes.iter().position(|&b| b != 0)?;
    Some(bytes[start..].to_vec())
}

fn point(x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    // SEC 2 secp256r1: affine coordinates must be field elements and satisfy
    // y^2 = x^3 - 3x + b (mod p). Only public JWKS data enters this check.
    static P: LazyLock<BigUint> = LazyLock::new(|| {
        BigUint::parse_bytes(
            b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap()
    });
    static B: LazyLock<BigUint> = LazyLock::new(|| {
        BigUint::parse_bytes(
            b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
            16,
        )
        .unwrap()
    });
    let (u, v) = (BigUint::from_bytes_be(x), BigUint::from_bytes_be(y));
    if u >= *P || v >= *P || (&v * &v + &u * 3u8) % &*P != (&u * &u * &u + &*B) % &*P {
        return None;
    }
    Some([&[4][..], x, y].concat())
}

fn key_ops(value: &RawValue, previous: &mut Vec<bool>) -> Option<bool> {
    let ops: Option<Vec<Option<String>>> = serde_json::from_str(value.get()).ok()?;
    let Some(ops) = ops else {
        previous.clear();
        return Some(true);
    };
    if ops.is_empty() {
        previous.clear();
        return Some(false);
    }
    // Go reuses a slice for repeated struct fields. A null in []string leaves
    // the element unchanged. Track just whether each slot contained "verify".
    let len = ops.len();
    if previous.len() < len {
        previous.resize(len, false);
    }
    for (slot, op) in previous.iter_mut().zip(ops) {
        if let Some(name) = op {
            *slot = name == "verify";
        }
    }
    Some(previous[..len].contains(&true))
}

fn parse_key(raw: &RawValue) -> Option<(String, Key)> {
    let mut fields = BTreeMap::<String, String>::new();
    let mut previous_ops = Vec::new();
    let mut can_verify = true;
    for (name, value) in serde_json::from_str::<Members>(raw.get()).ok()?.0 {
        if matches!(
            name.as_str(),
            "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k"
        ) {
            return None;
        }
        let name = field_name(&name);
        match name.as_str() {
            "key_ops" => can_verify = key_ops(value, &mut previous_ops)?,
            "kid" | "kty" | "use" | "alg" | "n" | "e" | "crv" | "x" | "y"
                if value.get() != "null" =>
            {
                fields.insert(name, serde_json::from_str(value.get()).ok()?);
            }
            _ => (),
        }
    }
    let get = |key: &str| fields.get(key).map_or("", String::as_str);
    if get("kid").is_empty() || !matches!(get("use"), "" | "sig") || !can_verify {
        return None;
    }
    let key = match get("kty") {
        "RSA" if matches!(get("alg"), "" | "RS256") => {
            let n = unsigned(get("n"))?;
            let e = unsigned(get("e"))?;
            // Go accepts moduli above ring's 8192-bit limit. Reject the whole set.
            if n.len() > 1024
                || n.len() < 256
                || n.len() == 256 && n[0] < 128
                || n.last()? & 1 == 0
                || e.len() > 4
                || e.len() == 4 && e[0] >= 128
                || e.len() == 1 && e[0] < 3
                || e.last()? & 1 == 0
            {
                return None;
            }
            Key::Rsa(RsaPublicKeyComponents { n, e })
        }
        "EC" if get("crv") == "P-256" && matches!(get("alg"), "" | "ES256") => {
            Key::Ec(point(&decode(get("x"))?, &decode(get("y"))?)?)
        }
        _ => return None,
    };
    Some((get("kid").to_owned(), key))
}

pub(super) fn parse(bytes: &[u8]) -> Result<KeySet> {
    let invalid = || anyhow!(INVALID_KEYS);
    let mut list = None;
    let bytes = super::json::compatible(bytes).ok_or_else(invalid)?;
    for (name, value) in serde_json::from_slice::<Members>(&bytes)
        .map_err(|_| invalid())?
        .0
    {
        if field_name(&name) == "keys" {
            list = serde_json::from_str::<Option<Vec<&RawValue>>>(value.get())
                .map_err(|_| invalid())?;
        }
    }
    let mut keys = KeySet::new();
    for raw in list.filter(|v| !v.is_empty()).ok_or_else(invalid)? {
        let (kid, key) = parse_key(raw).ok_or_else(invalid)?;
        if keys.insert(kid, key).is_some() {
            return Err(invalid());
        }
    }
    Ok(keys)
}
