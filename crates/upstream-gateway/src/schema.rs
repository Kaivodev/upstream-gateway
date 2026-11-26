use crate::{config::StartupConfig, db::Db};
use deadpool_postgres::Pool;
use std::{path::Path, str::FromStr};
use tokio_postgres::error::SqlState;
use tonic::Status;

const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/001_gateway.sql")),
    (2, include_str!("../migrations/002_audit_times.sql")),
];
const VERSION: i32 = MIGRATIONS.last().unwrap().0;
const READ_VERSION: &str = "SELECT max(version) FROM gateway_migrations";

/// A plain PostgreSQL identifier suitable for a quoted grant target.
pub struct AppRole(String);

impl FromStr for AppRole {
    type Err = &'static str;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if !(1..=63).contains(&name.len())
            || !name
                .bytes()
                .enumerate()
                .all(|(i, b)| b.is_ascii_lowercase() || b == b'_' || i > 0 && b.is_ascii_digit())
        {
            return Err("app role must match [a-z_][a-z0-9_]{0,62}");
        }
        Ok(Self(name.to_owned()))
    }
}

/// Apply the schema as its owner. Only the database settings and CA are needed.
pub async fn migrate(path: &Path, app_role: Option<&AppRole>) -> anyhow::Result<i32> {
    let pool = StartupConfig::migration_pool(path)?;
    apply(&pool, app_role).await?;
    Ok(VERSION)
}

fn mismatch(actual: Option<i32>) -> Status {
    let actual = actual.map_or_else(|| "none (unmigrated)".to_owned(), |v| v.to_string());
    Status::failed_precondition(format!(
        "database schema version {actual}, expected {VERSION}. Please run upstream-gateway migrate"
    ))
}

pub(crate) async fn require_current(pool: &Pool) -> Result<(), Status> {
    let c = pool.get().await.db()?;
    let version = match c.query_one(READ_VERSION, &[]).await {
        Ok(row) => row.get(0),
        Err(e) if e.code() == Some(&SqlState::UNDEFINED_TABLE) => None,
        Err(e) => return Err(e).db(),
    };
    if version != Some(VERSION) {
        return Err(mismatch(version));
    }
    Ok(())
}

pub(crate) async fn apply(pool: &Pool, app_role: Option<&AppRole>) -> Result<(), Status> {
    let mut c = pool.get().await.db()?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .db()?;
    let row = tx
        .query_one(
            "SELECT quote_ident(current_schema()),
                    pg_advisory_xact_lock(hashtextextended(current_schema() || '.gateway_migrations', 0))",
            &[],
        )
        .await
        .db()?;
    let schema: Option<String> = row.get(0);
    let schema = schema.ok_or_else(|| Status::failed_precondition("no current database schema"))?;
    // Restrict all unqualified names in the migration scripts and grants to the locked schema.
    tx.batch_execute(&format!("SET LOCAL search_path TO {schema}"))
        .await
        .db()?;
    tx.batch_execute("CREATE TABLE IF NOT EXISTS gateway_migrations (version integer PRIMARY KEY)")
        .await
        .db()?;
    let version: Option<i32> = tx.query_one(READ_VERSION, &[]).await.db()?.get(0);
    if version.is_some_and(|v| !MIGRATIONS.iter().any(|&(n, _)| n == v)) {
        return Err(mismatch(version));
    }
    for &(n, sql) in MIGRATIONS {
        if n > version.unwrap_or(0) {
            tx.batch_execute(sql).await.db()?;
            tx.execute("INSERT INTO gateway_migrations VALUES ($1)", &[&n])
                .await
                .db()?;
        }
    }
    if let Some(AppRole(name)) = app_role {
        if tx
            .query_opt(
                "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1",
                &[name],
            )
            .await
            .db()?
            .is_none()
        {
            return Err(Status::failed_precondition(format!(
                "application role \"{name}\" does not exist"
            )));
        }
        let grants = format!(
            r#"GRANT USAGE ON SCHEMA {schema} TO "{name}";
               GRANT SELECT ON gateway_migrations TO "{name}";
               GRANT SELECT, INSERT ON gateway_identity, credentials, revocations TO "{name}";
               GRANT SELECT, INSERT, UPDATE ON executors, packages, commands, operations, attempts TO "{name}";
               GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO "{name}";"#
        );
        tx.batch_execute(&grants).await.db()?;
        // A table added by a later migration must get an explicit grant decision
        // above. Fail the migration instead of failing the gateway at run time.
        let ungranted: Vec<String> = tx
            .query(
                "SELECT c.relname::text FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
                    AND NOT has_table_privilege($1::name, c.oid, 'SELECT')
                  ORDER BY 1",
                &[name],
            )
            .await
            .db()?
            .iter()
            .map(|row| row.get(0))
            .collect();
        if !ungranted.is_empty() {
            return Err(Status::failed_precondition(format!(
                "tables without an application grant: {}",
                ungranted.join(", ")
            )));
        }
    }
    tx.commit().await.db()
}
