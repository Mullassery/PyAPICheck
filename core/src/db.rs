//! PostgreSQL persistence for discovered inventories and traffic records.
//!
//! Opt-in only: nothing elsewhere in `pyapicheck` calls into this module
//! unless a caller explicitly supplies a database URL (e.g. via the CLI's
//! `--db-url`). Uses runtime-checked `sqlx::query`/`query_scalar` rather
//! than the `query!`/`query_scalar!` macros, so building this crate never
//! requires a live database connection or an offline query cache —
//! `cargo build`/`cargo test` (without exercising these functions) work
//! with zero Postgres setup, matching Phase 1's build story.

use crate::model::{summarize, Inventory};
use crate::traffic::TrafficRecord;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

pub async fn connect(database_url: &str) -> Result<PgPool, String> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .map_err(|e| format!("failed to connect to database: {e}"))
}

/// Apply `core/migrations/*.sql`. Safe to call on every startup — each
/// migration only runs once, tracked in sqlx's `_sqlx_migrations` table.
pub async fn migrate(pool: &PgPool) -> Result<(), String> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| format!("migration failed: {e}"))
}

/// Persist a freshly discovered inventory and its endpoints as a new row
/// (history-preserving: re-discovering the same source creates a new
/// inventory rather than overwriting the last one). Returns the new
/// inventory's id.
pub async fn persist_inventory(pool: &PgPool, inventory: &Inventory) -> Result<i64, String> {
    let inventory_id: i64 = sqlx::query_scalar(
        "INSERT INTO inventories (source, title, api_version) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&inventory.source)
    .bind(&inventory.title)
    .bind(&inventory.api_version)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("failed to insert inventory: {e}"))?;

    for endpoint in &inventory.endpoints {
        let endpoint_json = serde_json::to_value(endpoint).map_err(|e| {
            format!(
                "failed to serialize endpoint {} {}: {e}",
                endpoint.method, endpoint.path
            )
        })?;

        sqlx::query(
            "INSERT INTO endpoints
                (inventory_id, method, path, authenticated, deprecated, risk_score, risk_level, endpoint_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (inventory_id, method, path) DO UPDATE SET
                authenticated = EXCLUDED.authenticated,
                deprecated = EXCLUDED.deprecated,
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                endpoint_json = EXCLUDED.endpoint_json",
        )
        .bind(inventory_id)
        .bind(&endpoint.method)
        .bind(&endpoint.path)
        .bind(endpoint.authenticated)
        .bind(endpoint.deprecated)
        .bind(endpoint.risk.score)
        .bind(&endpoint.risk.level)
        .bind(endpoint_json)
        .execute(pool)
        .await
        .map_err(|e| format!("failed to insert endpoint {} {}: {e}", endpoint.method, endpoint.path))?;
    }

    Ok(inventory_id)
}

/// Persist a batch of parsed traffic records against an existing inventory.
pub async fn persist_traffic(
    pool: &PgPool,
    inventory_id: i64,
    records: &[TrafficRecord],
) -> Result<(), String> {
    for record in records {
        sqlx::query(
            "INSERT INTO traffic_records (inventory_id, method, path, status, observed_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(inventory_id)
        .bind(&record.method)
        .bind(&record.path)
        .bind(i32::from(record.status))
        .bind(&record.timestamp)
        .execute(pool)
        .await
        .map_err(|e| format!("failed to insert traffic record: {e}"))?;
    }
    Ok(())
}

/// Re-read an inventory back from Postgres by id, reconstructing the same
/// `Inventory` shape `discover_from_file` produces (each endpoint round-trips
/// through its stored `endpoint_json`; the summary is recomputed rather than
/// also stored, so it can never drift from the endpoints it summarizes).
pub async fn load_inventory(pool: &PgPool, inventory_id: i64) -> Result<Inventory, String> {
    let header = sqlx::query("SELECT source, title, api_version FROM inventories WHERE id = $1")
        .bind(inventory_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("failed to load inventory {inventory_id}: {e}"))?
        .ok_or_else(|| format!("no inventory with id {inventory_id}"))?;

    let source: String = header.try_get("source").map_err(|e| e.to_string())?;
    let title: String = header.try_get("title").map_err(|e| e.to_string())?;
    let api_version: String = header.try_get("api_version").map_err(|e| e.to_string())?;

    let endpoint_rows = sqlx::query(
        "SELECT endpoint_json FROM endpoints WHERE inventory_id = $1 ORDER BY path, method",
    )
    .bind(inventory_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("failed to load endpoints for inventory {inventory_id}: {e}"))?;

    let mut endpoints = Vec::with_capacity(endpoint_rows.len());
    for row in endpoint_rows {
        let json: serde_json::Value = row.try_get("endpoint_json").map_err(|e| e.to_string())?;
        endpoints.push(
            serde_json::from_value(json)
                .map_err(|e| format!("failed to deserialize endpoint: {e}"))?,
        );
    }

    let summary = summarize(&endpoints);

    Ok(Inventory {
        source,
        title,
        api_version,
        endpoints,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration tests need a real, reachable Postgres — set `DATABASE_URL`
    /// (e.g. `postgres://postgres:test@localhost:55432/pyapicheck` against a
    /// `docker run postgres:16` container) to run them. Skipped, not failed,
    /// when unset, so `cargo test` stays zero-setup for everyone else; CI
    /// sets it via a `postgres:` service so these run for real on every push.
    async fn test_pool_or_skip() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = connect(&url).await.expect("connect to test database");
        migrate(&pool).await.expect("run migrations");
        Some(pool)
    }

    #[tokio::test]
    async fn round_trips_an_inventory_through_postgres() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };

        let inventory = crate::discover_from_str(
            include_str!("../tests/fixtures/sample-openapi.yaml"),
            "test-source",
        )
        .unwrap();

        let id = persist_inventory(&pool, &inventory).await.unwrap();
        let loaded = load_inventory(&pool, id).await.unwrap();

        assert_eq!(loaded.title, inventory.title);
        assert_eq!(loaded.endpoints.len(), inventory.endpoints.len());
        assert_eq!(
            loaded.summary.high_or_critical,
            inventory.summary.high_or_critical
        );

        let refund = loaded
            .endpoints
            .iter()
            .find(|e| e.path == "/api/v1/refunds")
            .unwrap();
        assert_eq!(refund.risk.level, "CRITICAL");
    }

    #[tokio::test]
    async fn upserting_the_same_inventory_source_creates_a_new_history_row() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };

        let inventory = crate::discover_from_str(
            include_str!("../tests/fixtures/sample-openapi.yaml"),
            "test-source-2",
        )
        .unwrap();

        let first_id = persist_inventory(&pool, &inventory).await.unwrap();
        let second_id = persist_inventory(&pool, &inventory).await.unwrap();
        assert_ne!(first_id, second_id);
    }

    #[tokio::test]
    async fn persists_and_counts_traffic_records() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };

        let inventory = crate::discover_from_str(
            include_str!("../tests/fixtures/sample-openapi.yaml"),
            "test-source-3",
        )
        .unwrap();
        let inventory_id = persist_inventory(&pool, &inventory).await.unwrap();

        let records = crate::parse_access_log(
            r#"{"request_method": "GET", "request_uri": "/api/v1/health", "status": 200}"#,
        );
        persist_traffic(&pool, inventory_id, &records)
            .await
            .unwrap();

        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM traffic_records WHERE inventory_id = $1")
                .bind(inventory_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }
}
