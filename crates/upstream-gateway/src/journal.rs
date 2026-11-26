use crate::{
    Gateway, Role,
    api::ExecutionCategory,
    business::{Material, Outcome, Reply},
    crypto::aad,
    db::{self, Db, unavailable},
    encoding::{Encoder, hash},
};
use prost::Message;
use tokio_postgres::{Row, Transaction};
use tonic::Status;
use upstream_host::{
    environment::{CapturedResponse, Dispatch},
    types::HttpRequest,
};
use uuid::Uuid;

pub(crate) enum Claim {
    Done(Vec<u8>),
    Wait,
    Run(Lease),
}
#[derive(Clone)]
pub(crate) struct Lease {
    pub exchange: String,
    pub generation: i64,
    pub caller: String,
    pub blocked: bool,
}
pub(crate) struct Receipt {
    number: i32,
    request: Option<Vec<u8>>,
    reception: Vec<u8>,
    received: bool,
    code: String,
}
impl Lease {
    fn context(&self, g: &Gateway, part: &str, n: i32) -> Vec<u8> {
        g.evidence_aad(&self.caller, &self.exchange, &format!("{part}/{n}"))
    }
    async fn lock(&self, g: &Gateway, tx: &Transaction<'_>) -> Result<Row, Status> {
        g.active(tx).await?;
        tx.query_opt(
            "SELECT * FROM operations WHERE exchange=$1 AND executor=$2 AND generation=$3 AND
         terminal IS NULL FOR UPDATE",
            &[&self.exchange, &g.0.executor, &self.generation],
        )
        .await
        .db()?
        .ok_or_else(unavailable)
    }
    pub async fn select(&self, g: &Gateway, digest: &[u8]) -> Result<Option<&'static str>, Status> {
        let mut c = g.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        self.lock(g, &tx).await?;
        if db::gate(&tx, digest).await? && self.blocked {
            return Ok(Some("package_revoked"));
        }
        if tx
            .query_opt(
                "SELECT 1 FROM packages WHERE digest=$1 AND ready",
                &[&digest],
            )
            .await
            .db()?
            .is_none()
        {
            return Ok(Some("package_unavailable"));
        }
        tx.execute(
            "UPDATE operations SET selected=$2 WHERE exchange=$1",
            &[&self.exchange, &digest],
        )
        .await
        .db()?;
        tx.commit().await.db()?;
        Ok(None)
    }
    pub async fn authorize(
        &self,
        g: &Gateway,
        n: usize,
        r: &HttpRequest,
    ) -> Result<Dispatch, Status> {
        let n = n as i32;
        let sealed = g.0.vault.seal(
            &Encoder::attempt(n as usize, r).0,
            &self.context(g, "request", n),
        )?;
        let mut c = g.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        let row = self.lock(g, &tx).await?;
        if row.get::<_, i32>("requests") != n - 1 || row.get::<_, i32>("responses") != n - 1 {
            return Err(unavailable());
        }
        let selected: Vec<u8> = row.try_get("selected").db()?;
        if n == 1 && self.blocked && db::gate(&tx, &selected).await? {
            return Ok(Dispatch::Denied("package_revoked"));
        }
        tx.execute(
            "INSERT INTO attempts(exchange,number,request) VALUES($1,$2,$3)",
            &[&self.exchange, &n, &sealed],
        )
        .await
        .db()?;
        tx.execute(
            "UPDATE operations SET requests=$2,steps=$2 WHERE exchange=$1",
            &[&self.exchange, &n],
        )
        .await
        .db()?;
        tx.commit().await.db()?;
        #[cfg(test)]
        if g.0
            .unconfirm
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(Dispatch::Unconfirmed);
        }
        Ok(Dispatch::Granted)
    }
    pub fn receipt(
        &self,
        g: &Gateway,
        n: usize,
        r: &HttpRequest,
        response: Option<&CapturedResponse>,
        code: &str,
    ) -> Result<Receipt, Status> {
        let request = (code == "dispatch_unconfirmed")
            .then(|| {
                g.0.vault.seal(
                    &Encoder::attempt(n, r).0,
                    &self.context(g, "request", n as i32),
                )
            })
            .transpose()?;
        let reception = g.0.vault.seal(
            &Encoder::reception(response, code),
            &self.context(g, "response", n as i32),
        )?;
        Ok(Receipt {
            number: n as i32,
            request,
            reception,
            received: response.is_some(),
            code: code.into(),
        })
    }
    pub async fn record(&self, g: &Gateway, receipt: &Receipt) -> Result<(), Status> {
        let mut c = g.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        let row = self.lock(g, &tx).await?;
        let n = receipt.number;
        if row.get::<_, i32>("requests") == n - 1 && receipt.code == "dispatch_unconfirmed" {
            tx.execute(
                "INSERT INTO attempts(exchange,number,request) VALUES($1,$2,$3)",
                &[&self.exchange, &n, &receipt.request],
            )
            .await
            .db()?;
            tx.execute(
                "UPDATE operations SET requests=$2,steps=$2 WHERE exchange=$1",
                &[&self.exchange, &n],
            )
            .await
            .db()?;
        } else if row.get::<_, i32>("requests") != n {
            return Err(unavailable());
        }
        let changed = tx
            .execute(
                "UPDATE attempts SET reception=$3, outcome=$4, received_at=CASE WHEN $5 THEN clock_timestamp() END
                 WHERE exchange=$1 AND number=$2 AND reception IS NULL",
                &[&self.exchange, &n, &receipt.reception, &receipt.code, &receipt.received],
            )
            .await
            .db()?;
        if changed == 1 {
            tx.execute(
                "UPDATE operations SET responses=responses+$2, quarantine=quarantine OR $3 WHERE
             exchange=$1",
                &[
                    &self.exchange,
                    &i32::from(receipt.code.is_empty()),
                    &(receipt.code == "secret_leak"),
                ],
            )
            .await
            .db()?;
        }
        tx.commit().await.db()
    }
    pub async fn finish(&self, g: &Gateway, out: Outcome) -> Result<Vec<u8>, Status> {
        let mut c = g.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        // A previous commit may have been acknowledged by PostgreSQL only.
        if let Some(bytes) = tx
            .query_one(
                "SELECT terminal FROM operations WHERE exchange=$1",
                &[&self.exchange],
            )
            .await
            .db()?
            .get::<_, Option<Vec<u8>>>(0)
        {
            return Ok(bytes);
        }
        let row = self.lock(g, &tx).await?;
        let event = out.completion_event(row.get("method"));
        let response = g.terminal(&tx, row, out).await?;
        tx.commit().await.db()?;
        if let Some(code) = event {
            g.0.events.completion(code);
        }
        Ok(response)
    }
}
impl Gateway {
    pub(crate) async fn availability(
        &self,
        digest: &[u8],
        blocked: bool,
    ) -> Result<Option<&'static str>, Status> {
        let c = self.0.pool.get().await.db()?;
        let row = c
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM revocations WHERE digest=$1), EXISTS(SELECT 1 FROM
         packages WHERE digest=$1 AND ready)",
                &[&digest],
            )
            .await
            .db()?;
        Ok(if blocked && row.get(0) {
            Some("package_revoked")
        } else if !row.get::<_, bool>(1) {
            Some("package_unavailable")
        } else {
            None
        })
    }
    pub(crate) fn evidence_aad(&self, caller: &str, id: &str, part: &str) -> Vec<u8> {
        aad(
            "aipay.upstream.evidence.v1",
            self.0.role,
            &[id, caller, part],
        )
    }
    async fn active(&self, tx: &Transaction<'_>) -> Result<(), Status> {
        if self.needs_restart() {
            return Err(unavailable());
        }
        if tx
            .query_opt(
                "SELECT 1 FROM executors WHERE id=$1 AND NOT fenced FOR SHARE",
                &[&self.0.executor],
            )
            .await
            .db()?
            .is_none()
        {
            return Err(unavailable());
        }
        Ok(())
    }
    /// Waiters only return to the claiming transaction once recovery releases ownership.
    pub(crate) async fn observe(&self, caller: &str, key: &str) -> Result<Option<Claim>, Status> {
        let c = self.0.pool.get().await.db()?;
        let row = c
            .query_one(
                "SELECT terminal, executor FROM operations WHERE caller=$1 AND key=$2",
                &[&caller, &key],
            )
            .await
            .db()?;
        Ok(if let Some(bytes) = row.get(0) {
            Some(Claim::Done(bytes))
        } else if row.get::<_, Option<&str>>(1).is_some() {
            Some(Claim::Wait)
        } else {
            None
        })
    }
    pub(crate) async fn claim(&self, caller: &str, m: &Material) -> Result<Claim, Status> {
        let key = &m.context.idempotency_key;
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        let new_id = Uuid::now_v7().to_string();
        let inserted = tx
            .execute(
                "INSERT INTO operations(exchange, caller, key, method, digest, executor)
         VALUES($1, $2, $3, $4, $5, $6) ON CONFLICT(caller, key) DO NOTHING",
                &[
                    &new_id,
                    &caller,
                    &key,
                    &m.method,
                    &m.digest,
                    &self.0.executor,
                ],
            )
            .await
            .db()?;
        if inserted == 1
            && let Some(callback) = &m.callback
        {
            let mut e = Encoder::default();
            e.callback(callback);
            let sealed = self
                .0
                .vault
                .seal(&e.0, &self.evidence_aad(caller, &new_id, "callback"))?;
            tx.execute(
                "UPDATE operations SET callback=$2 WHERE exchange=$1",
                &[&new_id, &sealed],
            )
            .await
            .db()?;
        }
        let row = tx
            .query_one(
                "SELECT exchange, digest, method, terminal, generation, executor FROM operations
         WHERE caller=$1 AND key=$2 FOR UPDATE",
                &[&caller, &key],
            )
            .await
            .db()?;
        if row.get::<_, Vec<u8>>(1) != m.digest || row.get::<_, &str>(2) != m.method {
            return Err(db::conflict());
        }
        let action = if let Some(bytes) = row.get::<_, Option<Vec<u8>>>(3) {
            Claim::Done(bytes)
        } else if inserted == 1 || row.get::<_, Option<&str>>(5).is_none() {
            self.active(&tx).await?;
            let exchange: String = row.get(0);
            if inserted == 0 {
                tx.execute(
                    "UPDATE operations SET executor=$2 WHERE exchange=$1 AND executor IS NULL AND
                 terminal IS NULL",
                    &[&exchange, &self.0.executor],
                )
                .await
                .db()?;
            }
            Claim::Run(Lease {
                exchange,
                generation: row.get(4),
                caller: caller.into(),
                blocked: self.0.role == Role::Verification
                    || matches!(m.op, "refund" | "create_payment"),
            })
        } else {
            Claim::Wait
        };
        if tx.commit().await.is_err() {
            // An unacknowledged claim may now point at this healthy process
            // without a running worker. Fence it before handing off ownership.
            if matches!(action, Claim::Run(_)) {
                drop(c);
                self.retire().await?
            }
            return Err(unavailable());
        }
        Ok(action)
    }
    async fn terminal(
        &self,
        tx: &Transaction<'_>,
        row: Row,
        mut out: Outcome,
    ) -> Result<Vec<u8>, Status> {
        let x = &mut out.result;
        let id: &str = row.get("exchange");
        let caller: &str = row.get("caller");
        x.exchange_id = id.into();
        x.package_sha256 = row
            .get::<_, Option<Vec<u8>>>("selected")
            .unwrap_or_default();
        if x.requests != row.get::<_, i32>("requests") as u32
            || x.responses != row.get::<_, i32>("responses") as u32
        {
            return Err(unavailable());
        }
        let mut e = Encoder::domain("aipay.upstream.exchange.v1", caller, row.get("method"));
        e.string(id);
        e.bytes(row.get("digest"));
        e.bytes(&x.package_sha256);
        let callback = row
            .get::<_, Option<&[u8]>>("callback")
            .map(|v| {
                self.0
                    .vault
                    .open(v, &self.evidence_aad(caller, id, "callback"))
            })
            .transpose()?;
        e.optional(callback, |e, b| e.0.extend(&*b));
        let attempts = tx
            .query(
                "SELECT number, request, reception FROM attempts WHERE exchange=$1 ORDER BY
                 number",
                &[&id],
            )
            .await
            .db()?;
        if attempts.len() != x.requests as usize {
            return Err(unavailable());
        }
        e.u32(x.requests);
        for (index, a) in attempts.into_iter().enumerate() {
            let n: i32 = a.get(0);
            if n as usize != index + 1 {
                return Err(unavailable());
            }
            e.0.extend(&*self.0.vault.open(
                a.get(1),
                &self.evidence_aad(caller, id, &format!("request/{n}")),
            )?);
            match a.get::<_, Option<&[u8]>>(2) {
                Some(bytes) => e.0.extend(&*self.0.vault.open(
                    bytes,
                    &self.evidence_aad(caller, id, &format!("response/{n}")),
                )?),
                None if x.error_code == "dispatch_interrupted" => {
                    e.0.extend(Encoder::reception(None, "dispatch_interrupted"))
                }
                None => return Err(unavailable()),
            }
        }
        e.finish(x, out.canonical.as_deref());
        x.evidence_sha256 = hash(&e.0);
        let quarantine = x.error_code == "secret_leak" || row.get::<_, bool>("quarantine");
        let part = if quarantine { "quarantine" } else { "record" };
        let sealed = self
            .0
            .vault
            .seal(&e.0, &self.evidence_aad(caller, id, part))?;
        let bytes = Reply {
            execution: Some(x.clone()),
            output: out.output,
        }
        .encode_to_vec();
        let changed = tx
            .execute(
                "UPDATE operations SET terminal=$2, completed_at=clock_timestamp(), evidence=$3, evidence_hash=$4, steps=$5,
         quarantine=$6 WHERE exchange=$1 AND terminal IS NULL AND generation=$7",
                &[
                    &id,
                    &bytes,
                    &sealed,
                    &x.evidence_sha256,
                    &(x.steps as i32),
                    &quarantine,
                    &row.get::<_, i64>("generation"),
                ],
            )
            .await
            .db()?;
        if changed != 1 {
            return Err(unavailable());
        }
        Ok(bytes)
    }
    pub(crate) async fn maintain(&self) -> Result<(), Status> {
        self.refresh().await?;
        self.recover().await
    }
    pub(crate) async fn refresh(&self) -> Result<(), Status> {
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        let updated = tx
            .execute(
                "UPDATE executors SET heartbeat=clock_timestamp(), fenced=$2 WHERE id=$1 AND NOT
             fenced",
                &[&self.0.executor, &self.needs_restart()],
            )
            .await
            .db()?;
        tx.execute(
            "UPDATE executors SET fenced=true WHERE NOT fenced AND heartbeat <
         clock_timestamp()-($1::bigint * interval '1 millisecond')",
            &[&self.0.timing.fence_ms],
        )
        .await
        .db()?;
        tx.commit().await.db()?;
        if updated == 0 {
            self.0
                .lifecycle
                .send_replace(crate::health::Lifecycle::RestartRequired);
        }
        Ok(())
    }
    pub(crate) async fn recover(&self) -> Result<(), Status> {
        let mut c = self.0.pool.get().await.db()?;
        loop {
            let tx = c.transaction().await.db()?;
            let Some(row)=tx.query_opt("SELECT o.* FROM operations o JOIN executors e ON e.id=o.executor WHERE e.fenced
             AND o.terminal IS NULL LIMIT 1 FOR UPDATE OF o SKIP LOCKED",&[]).await.db()? else{tx.commit().await.db()?;break};
            if row.get::<_, i32>("requests") == 0 {
                tx.execute(
                    "UPDATE operations SET executor=NULL, generation=generation+1, selected=NULL,
                 steps=0 WHERE exchange=$1 AND generation=$2 AND terminal IS NULL",
                    &[
                        &row.get::<_, &str>("exchange"),
                        &row.get::<_, i64>("generation"),
                    ],
                )
                .await
                .db()?;
            } else {
                let mut out = Outcome::failure("dispatch_interrupted");
                let x = &mut out.result;
                x.category = ExecutionCategory::Unknown.into();
                x.requests = row.get::<_, i32>("requests") as u32;
                x.responses = row.get::<_, i32>("responses") as u32;
                x.steps = row.get::<_, i32>("steps") as u32;
                self.terminal(&tx, row, out).await?;
            }
            tx.commit().await.db()?;
        }
        Ok(())
    }
}
