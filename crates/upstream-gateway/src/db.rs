use crate::{Mode, Role, db_tls::DatabaseTls};
use deadpool_postgres::{Manager, Pool};
use std::{path::Path, time::Duration};
use tokio_postgres::{Config, NoTls, Transaction};
use tonic::Status;

pub(crate) trait Db<T> {
    fn db(self) -> Result<T, Status>;
}
// Keep raw SQL errors out of statuses and logs. The private cause carries
// only retry eligibility across the journal's status-based interface.
#[derive(Debug)]
struct Temporary;
impl std::fmt::Display for Temporary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("temporary storage failure")
    }
}
impl std::error::Error for Temporary {}
pub(crate) fn retryable(status: &Status) -> bool {
    std::error::Error::source(status).is_some_and(|e| e.is::<Temporary>())
}
fn storage_error(temporary: bool) -> Status {
    let mut status = unavailable();
    if temporary {
        status.set_source(std::sync::Arc::new(Temporary));
    }
    status
}
fn transient_pg(e: &tokio_postgres::Error) -> bool {
    use std::error::Error;
    e.is_closed()
        || e.source().is_some_and(|e| e.is::<std::io::Error>())
        || e.code().is_some_and(|code| {
            let code = code.code();
            code.starts_with("08")
                || code.starts_with("40")
                || code.starts_with("53")
                || matches!(code, "55P03" | "57014" | "57P01" | "57P02" | "57P03")
        })
}
impl<T> Db<T> for Result<T, tokio_postgres::Error> {
    fn db(self) -> Result<T, Status> {
        self.map_err(|e| storage_error(transient_pg(&e)))
    }
}
impl<T> Db<T> for Result<T, deadpool_postgres::PoolError> {
    fn db(self) -> Result<T, Status> {
        use deadpool_postgres::PoolError;
        self.map_err(|e| {
            storage_error(match e {
                PoolError::Timeout(_) => true,
                PoolError::Backend(e) => transient_pg(&e),
                _ => false,
            })
        })
    }
}
impl<T> Db<T> for Result<T, tokio::task::JoinError> {
    fn db(self) -> Result<T, Status> {
        self.map_err(|_| unavailable())
    }
}
pub(crate) fn unavailable() -> Status {
    Status::unavailable("gateway storage unavailable")
}
pub(crate) fn conflict() -> Status {
    Status::already_exists("idempotency key conflict")
}
pub(crate) fn precondition() -> Status {
    Status::failed_precondition("package admission failed")
}
/// Creates a development pool without a database CA bundle.
pub fn pool(config: Config) -> Result<Pool, Status> {
    let mode = Mode::Development {
        allow_loopback_http: false,
        allow_private_http: false,
        allow_uncommitted: false,
    };
    configured_pool(config, mode, None, 16).map_err(|_| unavailable())
}

pub(crate) fn configured_pool(
    mut config: Config,
    mode: Mode,
    ca: Option<&Path>,
    max_connections: usize,
) -> anyhow::Result<Pool> {
    let tls = DatabaseTls::configure(&config, mode, ca)?;
    config.connect_timeout(Duration::from_secs(5));
    config.options(format!(
        "{} -c statement_timeout=5000 -c idle_in_transaction_session_timeout=10000",
        config.get_options().unwrap_or("")
    ));
    let manager = match tls {
        Some(tls) => Manager::new(config, tls),
        None => Manager::new(config, NoTls),
    };
    Ok(Pool::builder(manager)
        .max_size(max_connections)
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .wait_timeout(Some(Duration::from_secs(5)))
        .build()
        .map_err(|_| unavailable())?)
}
pub(crate) async fn migrate(
    pool: &Pool,
    role: Role,
    vault: &crate::crypto::Vault,
) -> Result<crate::callback::Fingerprints, Status> {
    let aad = crate::crypto::aad("aipay.upstream.callback-fingerprints.v1", role, &[]);
    let mut c = pool.get().await.db()?;
    let tx = c.transaction().await.db()?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(current_schema() ||
     '.gateway_migrations', 0))",
        &[],
    )
    .await
    .db()?;
    tx.batch_execute("CREATE TABLE IF NOT EXISTS gateway_migrations (version integer PRIMARY KEY)")
        .await
        .db()?;
    let version: Option<i32> = tx
        .query_one("SELECT max(version) FROM gateway_migrations", &[])
        .await
        .db()?
        .get(0);
    match version {
        None => {
            tx.batch_execute(include_str!("../migrations/001_gateway.sql"))
                .await
                .db()?;
            tx.execute("INSERT INTO gateway_migrations VALUES (1)", &[])
                .await
                .db()?;
            let mut key = zeroize::Zeroizing::new([0; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| unavailable())?;
            let sealed = vault.seal(key.as_ref(), &aad)?;
            tx.execute(
                "INSERT INTO gateway_identity(role,fingerprint_key) VALUES($1,$2)",
                &[&role.name(), &sealed],
            )
            .await
            .db()?;
        }
        Some(1 | 2) => {}
        _ => return Err(Status::failed_precondition("unsupported schema version")),
    }
    if version != Some(2) {
        tx.batch_execute(include_str!("../migrations/002_audit_times.sql"))
            .await
            .db()?;
        tx.execute("INSERT INTO gateway_migrations VALUES (2)", &[])
            .await
            .db()?;
    }
    let row = tx
        .query_one(
            "SELECT role,fingerprint_key FROM gateway_identity WHERE singleton",
            &[],
        )
        .await
        .db()?;
    if row.get::<_, &str>(0) != role.name() {
        return Err(Status::failed_precondition("database role mismatch"));
    }
    let key = vault.open(row.get(1), &aad)?;
    tx.commit().await.db()?;
    Ok(crate::callback::Fingerprints::new(&key))
}
/// Serializes even an as-yet unknown package digest with its permanent tombstone.
pub(crate) async fn gate(tx: &Transaction<'_>, digest: &[u8]) -> Result<bool, Status> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea, 'hex'), 1))",
        &[&digest],
    )
    .await
    .db()?;
    Ok(tx
        .query_opt("SELECT 1 FROM revocations WHERE digest=$1", &[&digest])
        .await
        .db()?
        .is_some())
}
pub(crate) async fn command(
    tx: &Transaction<'_>,
    caller: &str,
    method: &str,
    key: &str,
    binding: &[u8],
) -> Result<Option<Vec<u8>>, Status> {
    tx.execute(
        "INSERT INTO commands(caller, method, key, digest) VALUES($1, $2, $3, $4) ON
         CONFLICT DO NOTHING",
        &[&caller, &method, &key, &binding],
    )
    .await
    .db()?;
    let row = tx
        .query_one(
            "SELECT digest, response FROM commands WHERE caller=$1 AND method=$2 AND key=$3
     FOR UPDATE",
            &[&caller, &method, &key],
        )
        .await
        .db()?;
    if row.get::<_, Vec<u8>>(0) != binding {
        return Err(conflict());
    }
    Ok(row.get(1))
}
pub(crate) async fn complete_command(
    tx: &Transaction<'_>,
    caller: &str,
    method: &str,
    key: &str,
    response: Vec<u8>,
) -> Result<(), Status> {
    if tx
        .execute(
            "UPDATE commands SET response=$4 WHERE caller=$1 AND method=$2 AND key=$3 AND
     response IS NULL",
            &[&caller, &method, &key, &response],
        )
        .await
        .db()?
        != 1
    {
        return Err(unavailable());
    }
    Ok(())
}
