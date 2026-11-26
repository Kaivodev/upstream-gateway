// Synthetic projected-token issuer shared by the verifier and real-process tests.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};

pub const ISSUER: &str = "https://synthetic-issuer.test";

pub struct Signer(EcdsaKeyPair);
impl Signer {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        let doc = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        Self(EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap())
    }

    pub fn jwk(&self) -> Value {
        let point = self.0.public_key().as_ref();
        json!({"kty":"EC","kid":"ec","crv":"P-256","x":B64.encode(&point[1..33]),"y":B64.encode(&point[33..])})
    }

    pub fn sign_raw(&self, header: &[u8], claims: &[u8]) -> String {
        let input = format!("{}.{}", B64.encode(header), B64.encode(claims));
        let signature = self.0.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        format!("{input}.{}", B64.encode(signature.as_ref()))
    }

    pub fn token(&self, claims: &Value) -> String {
        self.sign_raw(
            br#"{"alg":"ES256","kid":"ec"}"#,
            claims.to_string().as_bytes(),
        )
    }
}
pub fn claims(role: &str, caller: &str, now: i64) -> Value {
    json!({"iss":ISSUER,"aud":format!("kaivo:upstream-gateway-{role}"),
        "exp":now+600,"nbf":now,"iat":now,"sub":format!("system:serviceaccount:kaivo-business:{caller}")})
}
