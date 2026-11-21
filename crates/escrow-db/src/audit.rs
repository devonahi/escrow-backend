//! Append-only audit trail. It also serves as the "already sent" memory for reminders and announcements.

use chrono::{DateTime, Utc};
use crate::new_id;
use sqlx::PgExecutor;

pub async fn log<'e>(
    ex: impl PgExecutor<'e>,
    actor: &str,
    action: &str,
    target: &str,
    data: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log (id, actor, action, target, data) VALUES ($1,$2,$3,$4,$5)")
        .bind(new_id())
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(data)
        .execute(ex)
        .await
        .map(|_| ())
}

pub async fn exists<'e>(ex: impl PgExecutor<'e>, action: &str, target: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = $1 AND target = $2)")
        .bind(action)
        .bind(target)
        .fetch_one(ex)
        .await
}

pub async fn recent<'e>(ex: impl PgExecutor<'e>, limit: i64) -> Result<Vec<crate::models::AuditEntry>, sqlx::Error> {
    sqlx::query_as("SELECT id, actor, action, target, data, created_at FROM audit_log ORDER BY created_at DESC LIMIT $1")
        .bind(limit)
        .fetch_all(ex)
        .await
}

/// Counts anomaly_detected audit entries in the last 24 hours.
pub async fn count_anomalies_24h<'e>(ex: impl PgExecutor<'e>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'anomaly_detected' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .fetch_one(ex)
    .await
}
