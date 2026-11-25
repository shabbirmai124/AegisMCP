use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecordInput {
    pub run_id: String,
    pub tool_name: String,
    pub tier: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_us: u64,
    pub cache_hit: bool,
    pub status: String,
    pub trap_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub run_id: String,
    pub timestamp_utc: String,
    pub tool_name: String,
    pub tier: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_us: u64,
    pub cache_hit: bool,
    pub status: String,
    pub trap_reason: Option<String>,
    pub prev_hash: String,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub id: i64,
    pub run_id: String,
    pub timestamp_utc: String,
    pub prev_hash: String,
    pub receipt_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationReport {
    pub valid: bool,
    pub total_records: usize,
    pub broken_at_id: Option<i64>,
    pub broken_run_id: Option<String>,
    pub head_hash: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerification {
    pub found: bool,
    pub receipt_valid: bool,
    pub chain_valid: bool,
    pub record: Option<AuditRecord>,
    pub chain_report: ChainVerificationReport,
}

enum LedgerCommand {
    Append {
        input: AuditRecordInput,
        ack: oneshot::Sender<Result<AuditReceipt>>,
    },
}

#[derive(Clone)]
pub struct AuditLedger {
    db_path: PathBuf,
    tx: mpsc::Sender<LedgerCommand>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
pub fn compute_receipt_hash(
    prev_hash: &str,
    run_id: &str,
    timestamp_utc: &str,
    tool_name: &str,
    tier: &str,
    input_sha256: &str,
    output_sha256: &str,
    fuel_consumed: u64,
    peak_memory_bytes: usize,
    status: &str,
) -> String {
    let payload = format!(
        "{prev_hash}|{run_id}|{timestamp_utc}|{tool_name}|{tier}|{input_sha256}|{output_sha256}|{fuel_consumed}|{peak_memory_bytes}|{status}"
    );
    sha256_hex(payload.as_bytes())
}

fn configure_connection(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA busy_timeout = 5000;
        CREATE TABLE IF NOT EXISTS executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE NOT NULL,
            timestamp_utc TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            tier TEXT NOT NULL,
            input_sha256 TEXT NOT NULL,
            output_sha256 TEXT NOT NULL,
            fuel_consumed INTEGER NOT NULL,
            fuel_budget INTEGER NOT NULL,
            peak_memory_bytes INTEGER NOT NULL,
            duration_us INTEGER NOT NULL,
            cache_hit INTEGER NOT NULL,
            status TEXT NOT NULL,
            trap_reason TEXT,
            prev_hash TEXT NOT NULL,
            receipt_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_executions_run_id ON executions(run_id);
        ",
    )?;
    Ok(())
}

impl AuditLedger {
    pub fn open(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed opening SQLite ledger at {}", db_path.display()))?;
        configure_connection(&conn)?;

        let initial_head: String = conn
            .query_row(
                "SELECT receipt_hash FROM executions ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| GENESIS_HASH.to_string());

        let (tx, mut rx) = mpsc::channel::<LedgerCommand>(256);

        std::thread::Builder::new()
            .name("aegis-audit-writer".to_string())
            .spawn(move || {
                let mut head_hash = initial_head;
                while let Some(cmd) = rx.blocking_recv() {
                    match cmd {
                        LedgerCommand::Append { input, ack } => {
                            let res = append_row(&conn, &mut head_hash, input);
                            let _ = ack.send(res);
                        }
                    }
                }
            })
            .context("Failed spawning audit writer thread")?;

        Ok(Self {
            db_path: db_path.to_path_buf(),
            tx,
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub async fn record(&self, input: AuditRecordInput) -> Result<AuditReceipt> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(LedgerCommand::Append { input, ack: ack_tx })
            .await
            .map_err(|_| anyhow::anyhow!("Audit ledger writer channel closed"))?;
        ack_rx
            .await
            .map_err(|_| anyhow::anyhow!("Audit ledger writer dropped receipt"))?
    }

    pub fn verify_chain(&self) -> Result<ChainVerificationReport> {
        verify_chain(&self.db_path)
    }

    pub fn verify_receipt(&self, run_id: &str) -> Result<ReceiptVerification> {
        verify_receipt(&self.db_path, run_id)
    }

    pub fn recent(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        read_recent_records(&self.db_path, limit)
    }
}

fn append_row(
    conn: &Connection,
    head_hash: &mut String,
    input: AuditRecordInput,
) -> Result<AuditReceipt> {
    let timestamp_utc = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let prev_hash = head_hash.clone();
    let receipt_hash = compute_receipt_hash(
        &prev_hash,
        &input.run_id,
        &timestamp_utc,
        &input.tool_name,
        &input.tier,
        &input.input_sha256,
        &input.output_sha256,
        input.fuel_consumed,
        input.peak_memory_bytes,
        &input.status,
    );

    conn.execute(
        "INSERT INTO executions (
            run_id, timestamp_utc, tool_name, tier, input_sha256, output_sha256,
            fuel_consumed, fuel_budget, peak_memory_bytes, duration_us, cache_hit,
            status, trap_reason, prev_hash, receipt_hash
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            input.run_id,
            timestamp_utc,
            input.tool_name,
            input.tier,
            input.input_sha256,
            input.output_sha256,
            input.fuel_consumed as i64,
            input.fuel_budget as i64,
            input.peak_memory_bytes as i64,
            input.duration_us as i64,
            if input.cache_hit { 1i64 } else { 0i64 },
            input.status,
            input.trap_reason,
            prev_hash,
            receipt_hash,
        ],
    )?;

    let id = conn.last_insert_rowid();
    *head_hash = receipt_hash.clone();

    Ok(AuditReceipt {
        id,
        run_id: input.run_id,
        timestamp_utc,
        prev_hash,
        receipt_hash,
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        id: row.get(0)?,
        run_id: row.get(1)?,
        timestamp_utc: row.get(2)?,
        tool_name: row.get(3)?,
        tier: row.get(4)?,
        input_sha256: row.get(5)?,
        output_sha256: row.get(6)?,
        fuel_consumed: row.get::<_, i64>(7)? as u64,
        fuel_budget: row.get::<_, i64>(8)? as u64,
        peak_memory_bytes: row.get::<_, i64>(9)? as usize,
        duration_us: row.get::<_, i64>(10)? as u64,
        cache_hit: row.get::<_, i64>(11)? != 0,
        status: row.get(12)?,
        trap_reason: row.get(13)?,
        prev_hash: row.get(14)?,
        receipt_hash: row.get(15)?,
    })
}

pub fn verify_chain(db_path: &Path) -> Result<ChainVerificationReport> {
    if !db_path.exists() {
        return Ok(ChainVerificationReport {
            valid: true,
            total_records: 0,
            broken_at_id: None,
            broken_run_id: None,
            head_hash: GENESIS_HASH.to_string(),
            message: "Ledger does not exist yet (0 records; genesis valid)".into(),
        });
    }

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));

    let mut stmt = conn.prepare(
        "SELECT id, run_id, timestamp_utc, tool_name, tier, input_sha256, output_sha256,
                fuel_consumed, fuel_budget, peak_memory_bytes, duration_us, cache_hit,
                status, trap_reason, prev_hash, receipt_hash
         FROM executions
         ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], row_to_record)?;

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut total_records = 0usize;

    for row_res in rows {
        let rec = row_res?;
        total_records += 1;

        if rec.prev_hash != expected_prev {
            return Ok(ChainVerificationReport {
                valid: false,
                total_records,
                broken_at_id: Some(rec.id),
                broken_run_id: Some(rec.run_id),
                head_hash: expected_prev.clone(),
                message: format!(
                    "Chain link mismatch at row id {}: expected prev_hash {}, found {}",
                    rec.id, expected_prev, rec.prev_hash
                ),
            });
        }

        let recomputed = compute_receipt_hash(
            &rec.prev_hash,
            &rec.run_id,
            &rec.timestamp_utc,
            &rec.tool_name,
            &rec.tier,
            &rec.input_sha256,
            &rec.output_sha256,
            rec.fuel_consumed,
            rec.peak_memory_bytes,
            &rec.status,
        );

        if rec.receipt_hash != recomputed {
            return Ok(ChainVerificationReport {
                valid: false,
                total_records,
                broken_at_id: Some(rec.id),
                broken_run_id: Some(rec.run_id),
                head_hash: expected_prev,
                message: format!(
                    "Hash tamper detected at row id {}: stored {}, recomputed {}",
                    rec.id, rec.receipt_hash, recomputed
                ),
            });
        }

        expected_prev = rec.receipt_hash;
    }

    Ok(ChainVerificationReport {
        valid: true,
        total_records,
        broken_at_id: None,
        broken_run_id: None,
        head_hash: expected_prev,
        message: format!("Hash chain verified cleanly across {total_records} record(s)"),
    })
}

pub fn verify_receipt(db_path: &Path, run_id: &str) -> Result<ReceiptVerification> {
    let chain_report = verify_chain(db_path)?;
    if !db_path.exists() {
        return Ok(ReceiptVerification {
            found: false,
            receipt_valid: false,
            chain_valid: chain_report.valid,
            record: None,
            chain_report,
        });
    }

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    let record: Option<AuditRecord> = conn
        .query_row(
            "SELECT id, run_id, timestamp_utc, tool_name, tier, input_sha256, output_sha256,
                    fuel_consumed, fuel_budget, peak_memory_bytes, duration_us, cache_hit,
                    status, trap_reason, prev_hash, receipt_hash
             FROM executions
             WHERE run_id = ?1",
            params![run_id],
            row_to_record,
        )
        .ok();

    let found = record.is_some();
    let receipt_valid = match (&record, chain_report.broken_at_id) {
        (Some(rec), None) => {
            let expected = compute_receipt_hash(
                &rec.prev_hash,
                &rec.run_id,
                &rec.timestamp_utc,
                &rec.tool_name,
                &rec.tier,
                &rec.input_sha256,
                &rec.output_sha256,
                rec.fuel_consumed,
                rec.peak_memory_bytes,
                &rec.status,
            );
            rec.receipt_hash == expected
        }
        (Some(rec), Some(broken_id)) => rec.id < broken_id,
        (None, _) => false,
    };

    Ok(ReceiptVerification {
        found,
        receipt_valid,
        chain_valid: chain_report.valid,
        record,
        chain_report,
    })
}

pub fn read_recent_records(db_path: &Path, limit: usize) -> Result<Vec<AuditRecord>> {
    if !db_path.exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    let mut stmt = conn.prepare(
        "SELECT id, run_id, timestamp_utc, tool_name, tier, input_sha256, output_sha256,
                fuel_consumed, fuel_budget, peak_memory_bytes, duration_us, cache_hit,
                status, trap_reason, prev_hash, receipt_hash
         FROM executions
         ORDER BY id DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
