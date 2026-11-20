//! Strict JSON for fixture, manifest and simulator protocol boundaries.
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;
struct Node(usize);
impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Node {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("integer-only JSON, at most 64 containers deep")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.0 >= 64 {
            return Err(de::Error::custom("depth limit"));
        }
        let mut arr = Vec::new();
        while let Some(v) = a.next_element_seed(Node(self.0 + 1))? {
            arr.push(v)
        }
        Ok(Value::Array(arr))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        if self.0 >= 64 {
            return Err(de::Error::custom("depth limit"));
        }
        let mut map = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if map.contains_key(&k) {
                return Err(de::Error::custom("duplicate field"));
            }
            map.insert(k, a.next_value_seed(Node(self.0 + 1))?);
        }
        Ok(Value::Object(map))
    }
}
pub fn object(b: &[u8]) -> Option<Value> {
    if b.len() > 1 << 20 {
        return None;
    }
    let mut d = serde_json::Deserializer::from_slice(b);
    let v = Node(0).deserialize(&mut d).ok()?;
    d.end().ok()?;
    v.is_object().then_some(v)
}
