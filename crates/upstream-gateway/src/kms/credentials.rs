use super::{Failure, Http, json_object, object, open_regular, read_file};
use regex::Regex;
use serde::Deserialize;

use std::{
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::LazyLock,
};
use zeroize::Zeroizing;

pub(super) const STS: &str = "sts.googleapis.com";
pub(super) const IAM: &str = "iamcredentials.googleapis.com";
const STS_URL: &str = "https://sts.googleapis.com/v1/token";
const IAM_PREFIX: &str = "https://iamcredentials.googleapis.com";
const IAM_PATH: &str = "/v1/projects/-/serviceAccounts/";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";

static AUDIENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\A//iam\.googleapis\.com/projects/[0-9]+/locations/global",
        r"/workloadIdentityPools/[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+\z"
    ))
    .unwrap()
});
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com\z",
    )
    .unwrap()
});

#[derive(Deserialize)]
pub(super) struct ExternalAccount {
    r#type: String,
    #[serde(default = "google_universe")]
    universe_domain: String,
    audience: String,
    subject_token_type: String,
    token_url: String,
    service_account_impersonation_url: String,
    #[serde(deserialize_with = "object")]
    credential_source: Source,
}
fn google_universe() -> String {
    "googleapis.com".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    file: PathBuf,
    #[serde(default, deserialize_with = "object")]
    format: Format,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Format {
    r#type: String,
}

impl Default for Format {
    fn default() -> Self {
        Self {
            r#type: "text".into(),
        }
    }
}

impl ExternalAccount {
    pub(super) fn parse(reader: impl Read) -> Option<Self> {
        let mut json = serde_json::Deserializer::from_reader(reader);
        let config: Self = object(&mut json).ok()?;
        json.end().ok()?;
        let email = config
            .service_account_impersonation_url
            .strip_prefix(IAM_PREFIX)?
            .strip_prefix(IAM_PATH)?
            .strip_suffix(":generateAccessToken")?;
        (config.r#type == "external_account"
            && config.universe_domain == "googleapis.com"
            && config.subject_token_type == JWT
            && config.token_url == STS_URL
            && AUDIENCE.is_match(&config.audience)
            && EMAIL.is_match(email)
            && config.credential_source.file.is_absolute()
            && config.credential_source.format.r#type == "text")
            .then_some(config)
    }
}

// Encode directly into the zeroizing request buffer, including reserved bytes in the JWT.
fn form(fields: &[(&str, &str)]) -> Zeroizing<Vec<u8>> {
    let capacity = fields.iter().map(|(k, v)| k.len() + 2 + 3 * v.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    let hex = b"0123456789ABCDEF";
    for (key, value) in fields {
        if !out.is_empty() {
            out.push(b'&');
        }
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        for b in value.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => out.push(b),
                b' ' => out.push(b'+'),
                _ => out.extend_from_slice(&[b'%', hex[(b >> 4) as usize], hex[(b & 15) as usize]]),
            }
        }
    }
    out
}

#[derive(Deserialize)]
struct StsToken {
    #[serde(deserialize_with = "super::secret_string")]
    access_token: Zeroizing<String>,
}
#[derive(Deserialize)]
struct IamToken {
    #[serde(rename = "accessToken", deserialize_with = "super::secret_string")]
    access_token: Zeroizing<String>,
}

fn bearer(token: Zeroizing<String>, step: &'static str) -> Result<Zeroizing<String>, Failure> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Failure::invalid_response(step));
    }
    Ok(token)
}

pub(super) async fn authenticate(http: &Http, path: &Path) -> Result<Zeroizing<String>, Failure> {
    let path = path.to_owned();
    let config = tokio::task::spawn_blocking(move || {
        ExternalAccount::parse(BufReader::new(open_regular(&path).ok()?))
    })
    .await
    .ok()
    .flatten()
    .ok_or(Failure::new("credentials"))?;
    let sts_token = {
        let bytes = read_file(&config.credential_source.file)
            .await
            .map_err(|_| Failure::new("subject_token"))?;
        let token = std::str::from_utf8(&bytes)
            .ok()
            .map(|s| s.trim_matches(|c| matches!(c, ' ' | '\t'..='\r')))
            .filter(|s| !s.is_empty() && s.bytes().all(|b| (b' '..=b'~').contains(&b)))
            .ok_or(Failure::new("subject_token"))?;
        let body = form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("audience", &config.audience),
            ("scope", CLOUD_PLATFORM),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("subject_token", token),
            ("subject_token_type", JWT),
        ]);
        let response = http.post("sts", STS, "/v1/token", None, body).await?;
        let token: StsToken = json_object(&response).ok_or(Failure::invalid_response("sts"))?;
        bearer(token.access_token, "sts")?
    };
    let body = Zeroizing::new(
        br#"{"scope":["https://www.googleapis.com/auth/cloudkms"],"lifetime":"600s"}"#.to_vec(),
    );
    let response = http
        .post(
            "impersonation",
            IAM,
            &config.service_account_impersonation_url[IAM_PREFIX.len()..],
            Some(&sts_token),
            body,
        )
        .await?;
    let token: IamToken =
        json_object(&response).ok_or(Failure::invalid_response("impersonation"))?;
    bearer(token.access_token, "impersonation")
}
