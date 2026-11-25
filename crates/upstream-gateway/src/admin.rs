use crate::{
    Gateway, VerifiedCaller,
    api::*,
    business::{id, required, visible},
    crypto::{aad, credentials},
    db::{self, Db, precondition},
    encoding::{Encoder, hash},
    wire::{MESSAGE_LIMIT, invalid},
};
use prost::Message;
use std::{collections::BTreeMap, sync::Arc};
use tonic::Status;
use upstream_host::{
    engine::Loaded,
    package::{Manifest, Package, hex},
    replay::Replay,
};
use uuid::Uuid;
use zeroize::Zeroizing;

fn key(s: &str) -> Result<(), Status> {
    if visible(s, 128) {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn digest(d: &[u8]) -> Result<(), Status> {
    if d.len() == 32 {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn unpack(v: &PluginPackage) -> Result<Package, Status> {
    if v.encoded_len() > MESSAGE_LIMIT || v.plugin_wasm.is_empty() || v.plugin_wasm.len() > 4 << 20
    {
        return Err(precondition());
    }
    let manifest = Manifest::parse(&v.manifest_json).map_err(|_| precondition())?;
    if upstream_host::json::canonical(&serde_json::json!(manifest)) != v.manifest_json {
        return Err(precondition());
    }
    let fixtures = v
        .fixtures
        .iter()
        .map(|f| (f.path.clone(), f.content.clone()))
        .collect::<BTreeMap<_, _>>();
    if fixtures.len() != v.fixtures.len() {
        return Err(precondition());
    }
    let p = Package {
        manifest,
        wasm: v.plugin_wasm.clone(),
        fixtures,
    };
    p.validate_fixtures().map_err(|_| precondition())?;
    if p.hash() != hex(&v.package_sha256) {
        return Err(precondition());
    }
    Ok(p)
}
fn decoded<M: Message + Default>(bytes: &[u8]) -> Result<M, Status> {
    M::decode(bytes).map_err(|_| Status::data_loss("invalid stored response"))
}
fn admin_digest(caller: &str, method: &str, key: &str) -> Encoder {
    let mut e = Encoder::request(
        caller,
        &format!("/aipay.upstream.v1.UpstreamAdminService/{method}"),
    );
    e.string(key);
    e
}
impl Gateway {
    async fn replay_material(&self, v: PluginPackage) -> Result<(Package, PackageDigests), Status> {
        digest(&v.package_sha256)?;
        let role = self.0.role;
        let mode = self.0.mode;
        tokio::task::spawn_blocking(move || {
            let p = unpack(&v)?;
            if p.manifest.r#type != role.world()
                || !mode.allow_uncommitted() && p.manifest.build.source_commit == "uncommitted"
            {
                return Err(precondition());
            }
            let report = Replay::new(&p)
                .and_then(|r| r.run())
                .map_err(|_| precondition())?;
            if report["passed"] != true {
                return Err(precondition());
            }
            let fixture_hash = p.fixture_hash();
            let fixtures_sha256 = (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&fixture_hash[i..i + 2], 16).unwrap())
                .collect();
            Ok((
                p,
                PackageDigests {
                    package_sha256: v.package_sha256,
                    fixtures_sha256,
                    regression_report_sha256: hash(&upstream_host::json::canonical(&report)),
                },
            ))
        })
        .await
        .map_err(|_| precondition())?
    }
    pub async fn replay_package(
        &self,
        caller: VerifiedCaller,
        r: ReplayPackageRequest,
    ) -> Result<ReplayPackageResponse, Status> {
        self.authorize(&caller, false)?;
        crate::wire::check_size(&r)?;
        let (_, digests) = self.replay_material(required(r.package)?).await?;
        Ok(ReplayPackageResponse {
            digests: Some(digests),
        })
    }
    pub async fn register_package(
        &self,
        caller: VerifiedCaller,
        r: RegisterPackageRequest,
    ) -> Result<RegisterPackageResponse, Status> {
        self.authorize(&caller, false)?;
        crate::wire::check_size(&r)?;
        key(&r.idempotency_key)?;
        let name = "RegisterPackage";
        let caller = caller.name();
        let key = &r.idempotency_key;
        let v = required(r.package)?;
        let approved = required(r.approved_digests)?;
        let publication = required(r.publication)?;
        if v.encoded_len() > MESSAGE_LIMIT || !id(&publication.approval_request_id) {
            return Err(invalid());
        }
        for d in [
            &v.package_sha256,
            &approved.package_sha256,
            &approved.fixtures_sha256,
            &approved.regression_report_sha256,
            &publication.request_digest,
        ] {
            digest(d)?
        }
        let mut binding = admin_digest(caller, name, key);
        // The package-level binding excludes the command key so an identical publication can be resubmitted.
        let mut material = Encoder::default();
        material.package(&v);
        material.digests(&approved);
        material.string(&publication.approval_request_id);
        material.bytes(&publication.request_digest);
        binding.0.extend(&material.0);
        let binding = hash(&binding.0);
        let immutable = hash(&material.0);
        {
            let mut c = self.0.pool.get().await.db()?;
            let tx = c.transaction().await.db()?;
            let old = db::command(&tx, caller, name, key, &binding).await?;
            tx.commit().await.db()?;
            if let Some(old) = old {
                return decoded(&old);
            }
        }
        let blob = v.encode_to_vec();
        let (package, actual) = self.replay_material(v).await?;
        if actual != approved {
            return Err(precondition());
        }
        let digest = &actual.package_sha256;
        {
            let mut c = self.0.pool.get().await.db()?;
            let tx = c.transaction().await.db()?;
            if db::gate(&tx, digest).await? {
                return Err(precondition());
            }
            tx.execute(
                "INSERT INTO packages(digest, code, version, material, approval, binding)
             VALUES($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &digest,
                    &package.manifest.code,
                    &package.manifest.version,
                    &blob,
                    &publication.encode_to_vec(),
                    &immutable,
                ],
            )
            .await
            .db()?;
            let stored = tx
                .query_opt("SELECT binding FROM packages WHERE digest=$1", &[&digest])
                .await
                .db()?;
            if stored.is_none_or(|r| r.get::<_, Vec<u8>>(0) != immutable) {
                return Err(precondition());
            }
            tx.commit().await.db()?;
        }
        let host = self.0.host.clone();
        let loaded = tokio::task::spawn_blocking(move || host.load(&package))
            .await
            .map_err(|_| precondition())?
            .map_err(|_| precondition())?;
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        if let Some(old) = db::command(&tx, caller, name, key, &binding).await? {
            return decoded(&old);
        }
        if db::gate(&tx, digest).await? {
            return Err(precondition());
        }
        tx.execute("UPDATE packages SET ready=true WHERE digest=$1", &[&digest])
            .await
            .db()?;
        let result = RegisterPackageResponse {
            digests: Some(actual.clone()),
            publication: Some(publication),
        };
        db::complete_command(&tx, caller, name, key, result.encode_to_vec()).await?;
        tx.commit().await.db()?;
        self.0.cache.write().unwrap().insert(digest.clone(), loaded);
        Ok(result)
    }
    pub async fn revoke_package(
        &self,
        caller: VerifiedCaller,
        r: RevokePackageRequest,
    ) -> Result<RevokePackageResponse, Status> {
        self.authorize(&caller, false)?;
        crate::wire::check_size(&r)?;
        key(&r.idempotency_key)?;
        digest(&r.package_sha256)?;
        if !id(&r.owner_action_id) {
            return Err(invalid());
        }
        let name = "RevokePackage";
        let key = &r.idempotency_key;
        let caller = caller.name();
        let mut e = admin_digest(caller, name, key);
        e.bytes(&r.package_sha256);
        e.string(&r.owner_action_id);
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        if let Some(old) = db::command(&tx, caller, name, key, &hash(&e.0)).await? {
            return decoded(&old);
        }
        db::gate(&tx, &r.package_sha256).await?;
        tx.execute(
            "INSERT INTO revocations(digest, owner_action) VALUES($1, $2) ON CONFLICT DO
             NOTHING",
            &[&r.package_sha256, &r.owner_action_id],
        )
        .await
        .db()?;
        let t: std::time::SystemTime = tx
            .query_one(
                "SELECT revoked_at FROM revocations WHERE digest=$1",
                &[&r.package_sha256],
            )
            .await
            .db()?
            .get(0);
        let result = RevokePackageResponse {
            package_sha256: r.package_sha256,
            revoked_at: Some(t.into()),
        };
        db::complete_command(&tx, caller, name, key, result.encode_to_vec()).await?;
        tx.commit().await.db()?;
        Ok(result)
    }
    pub async fn store_credentials(
        &self,
        caller: VerifiedCaller,
        r: StoreCredentialsRequest,
    ) -> Result<StoreCredentialsResponse, Status> {
        self.authorize(&caller, false)?;
        crate::wire::check_size(&r)?;
        key(&r.idempotency_key)?;
        if !id(&r.channel_account_id)
            || !(2..=32).contains(&r.channel_code.len())
            || !r
                .channel_code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(invalid());
        }
        let secrets = credentials(&Zeroizing::new(r.credentials_json))?;
        let name = "StoreCredentials";
        let key = &r.idempotency_key;
        let caller = caller.name();
        let mut e = admin_digest(caller, name, key);
        e.string(&r.channel_account_id);
        e.string(&r.channel_code);
        e.bytes(&secrets.canonical);
        let binding = hash(&e.0);
        zeroize::Zeroize::zeroize(&mut e.0);
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        if let Some(old) = db::command(&tx, caller, name, key, &binding).await? {
            return decoded(&old);
        }
        let role = self.0.role;
        let reference = format!("{}:{}:{}", role.caller(), role.name(), Uuid::now_v7());
        let markers = self.0.fingerprints.describe(&secrets.values);
        let sealed = self.0.vault.seal(
            &secrets.canonical,
            &aad(
                "aipay.upstream.credentials.v1",
                role,
                &[&reference, &r.channel_account_id, &r.channel_code],
            ),
        )?;
        tx.execute(
            "INSERT INTO credentials(ref, channel, code, digest, names, markers, sealed)
         VALUES($1, $2, $3, $4, $5, $6, $7)",
            &[
                &reference,
                &r.channel_account_id,
                &r.channel_code,
                &secrets.digest,
                &secrets.values.keys().cloned().collect::<Vec<_>>(),
                &markers,
                &sealed,
            ],
        )
        .await
        .db()?;
        let result = StoreCredentialsResponse {
            credentials_ref: reference,
            credentials_sha256: secrets.digest,
        };
        db::complete_command(&tx, caller, name, key, result.encode_to_vec()).await?;
        tx.commit().await.db()?;
        Ok(result)
    }
    pub async fn get_exchange(
        &self,
        caller: VerifiedCaller,
        r: GetExchangeRequest,
    ) -> Result<GetExchangeResponse, Status> {
        if !id(&r.exchange_id) {
            return Err(invalid());
        }
        if caller.name() != self.0.role.caller() {
            return Err(Status::not_found("exchange not found"));
        }
        self.authorize(&caller, false)?;
        crate::wire::check_size(&r)?;
        let c = self.0.pool.get().await.db()?;
        let row = c
            .query_opt(
                "SELECT evidence, evidence_hash, quarantine FROM operations WHERE caller=$1 AND
         exchange=$2 AND terminal IS NOT NULL",
                &[&caller.name(), &r.exchange_id],
            )
            .await
            .db()?
            .ok_or_else(|| Status::not_found("exchange not found"))?;
        if row.get::<_, bool>(2) {
            return Err(Status::failed_precondition("exchange quarantined"));
        }
        let record = self.0.vault.open(
            row.get(0),
            &self.evidence_aad(caller.name(), &r.exchange_id, "record"),
        )?;
        let digest = hash(&record);
        if digest != row.get::<_, Vec<u8>>(1) {
            return Err(Status::data_loss("evidence digest mismatch"));
        }
        Ok(GetExchangeResponse {
            exchange_id: r.exchange_id,
            canonical_record: record.to_vec(),
            evidence_sha256: digest,
        })
    }
    pub(crate) async fn load_package(&self, digest: &[u8]) -> Result<Arc<Loaded>, Status> {
        if let Some(p) = self.0.cache.read().unwrap().get(digest).cloned() {
            return Ok(p);
        }
        let c = self.0.pool.get().await.db()?;
        let row = c
            .query_opt(
                "SELECT material FROM packages WHERE ready AND digest=$1",
                &[&digest],
            )
            .await
            .db()?
            .ok_or_else(precondition)?;
        let wire = decoded::<PluginPackage>(row.get(0))?;
        if wire.package_sha256 != digest {
            return Err(precondition());
        }
        let host = self.0.host.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            host.load(&unpack(&wire)?).map_err(|_| precondition())
        })
        .await
        .map_err(|_| precondition())??;
        self.0
            .cache
            .write()
            .unwrap()
            .insert(digest.to_vec(), loaded.clone());
        Ok(loaded)
    }
}
