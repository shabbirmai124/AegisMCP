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
    pub execution_id: String,
    pub tool_name: String,
    pub policy_tier: String,
    pub classification: String,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_ms: u64,
    pub code_sha256: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: i64,
    pub execution_id: String,
    pub timestamp_utc: String,
    pub tool_name: String,
    pub policy_tier: String,
    pub classification: String,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub peak_memory_bytes: usize,
    pub duration_ms: u64,
    pub code_sha256: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReceipt {
    pub seq: i64,
    pub execution_id: String,
    pub timestamp_utc: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationReport {
    pub valid: bool,
    pub total_records: usize,
    pub broken_at_seq: Option<i64>,
    pub broken_execution_id: Option<String>,
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
pub fn compute_entry_hash(
    prev_hash: &str,
    execution_id: &str,
    timestamp_utc: &str,
    tool_name: &str,
    policy_tier: &str,
    classification: &str,
    fuel_consumed: u64,
    fuel_budget: u64,
    peak_memory_bytes: usize,
    duration_ms: u64,
    code_sha256: &str,
    summary: &str,
) -> String {
    let payload = format!(
        "{prev_hash}|{execution_id}|{timestamp_utc}|{tool_name}|{policy_tier}|{classification}|{fuel_consumed}|{fuel_budget}|{peak_memory_bytes}|{duration_ms}|{code_sha256}|{summary}"
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
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id TEXT NOT NULL UNIQUE,
            timestamp_utc TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            policy_tier TEXT NOT NULL,
            classification TEXT NOT NULL,
            fuel_consumed INTEGER NOT NULL,
            fuel_budget INTEGER NOT NULL,
            peak_memory_bytes INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            code_sha256 TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_executions_exec_id ON executions(execution_id);
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
                "SELECT entry_hash FROM executions ORDER BY seq DESC LIMIT 1",
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
        verify_sqlite_chain(&self.db_path)
    }

    pub fn verify_receipt(&self, execution_id: &str) -> Result<ReceiptVerification> {
        verify_sqlite_receipt(&self.db_path, execution_id)
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
    let entry_hash = compute_entry_hash(
        &prev_hash,
        &input.execution_id,
        &timestamp_utc,
        &input.tool_name,
        &input.policy_tier,
        &input.classification,
        input.fuel_consumed,
        input.fuel_budget,
        input.peak_memory_bytes,
        input.duration_ms,
        &input.code_sha256,
        &input.summary,
    );

    conn.execute(
        "INSERT INTO executions (
            execution_id, timestamp_utc, tool_name, policy_tier, classification,
            fuel_consumed, fuel_budget, peak_memory_bytes, duration_ms, code_sha256,
            prev_hash, entry_hash, summary
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            input.execution_id,
            timestamp_utc,
            input.tool_name,
            input.policy_tier,
            input.classification,
            input.fuel_consumed as i64,
            input.fuel_budget as i64,
            input.peak_memory_bytes as i64,
            input.duration_ms as i64,
            input.code_sha256,
            prev_hash,
            entry_hash,
            input.summary,
        ],
    )?;

    let seq = conn.last_insert_rowid();
    *head_hash = entry_hash.clone();

    Ok(AuditReceipt {
        seq,
        execution_id: input.execution_id,
        timestamp_utc,
        prev_hash,
        entry_hash,
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        seq: row.get(0)?,
        execution_id: row.get(1)?,
        timestamp_utc: row.get(2)?,
        tool_name: row.get(3)?,
        policy_tier: row.get(4)?,
        classification: row.get(5)?,
        fuel_consumed: row.get::<_, i64>(6)? as u64,
        fuel_budget: row.get::<_, i64>(7)? as u64,
        peak_memory_bytes: row.get::<_, i64>(8)? as usize,
        duration_ms: row.get::<_, i64>(9)? as u64,
        code_sha256: row.get(10)?,
        prev_hash: row.get(11)?,
        entry_hash: row.get(12)?,
        summary: row.get(13)?,
    })
}

pub fn verify_sqlite_chain(db_path: &Path) -> Result<ChainVerificationReport> {
    if !db_path.exists() {
        return Ok(ChainVerificationReport {
            valid: true,
            total_records: 0,
            broken_at_seq: None,
            broken_execution_id: None,
            head_hash: GENESIS_HASH.to_string(),
            message: "Ledger does not exist yet (0 records; genesis valid)".into(),
        });
    }

    let conn = Connection::open(db_path)?;
    configure_connection(&conn)?;

    let mut stmt = conn.prepare(
        "SELECT seq, execution_id, timestamp_utc, tool_name, policy_tier, classification,
                fuel_consumed, fuel_budget, peak_memory_bytes, duration_ms, code_sha256,
                prev_hash, entry_hash, summary
         FROM executions
         ORDER BY seq ASC",
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
                broken_at_seq: Some(rec.seq),
                broken_execution_id: Some(rec.execution_id),
                head_hash: expected_prev.clone(),
                message: format!(
                    "Chain link mismatch at seq {}: expected prev_hash {}, found {}",
                    rec.seq, expected_prev, rec.prev_hash
                ),
            });
        }

        let recomputed = compute_entry_hash(
            &rec.prev_hash,
            &rec.execution_id,
            &rec.timestamp_utc,
            &rec.tool_name,
            &rec.policy_tier,
            &rec.classification,
            rec.fuel_consumed,
            rec.fuel_budget,
            rec.peak_memory_bytes,
            rec.duration_ms,
            &rec.code_sha256,
            &rec.summary,
        );

        if rec.entry_hash != recomputed {
            return Ok(ChainVerificationReport {
                valid: false,
                total_records,
                broken_at_seq: Some(rec.seq),
                broken_execution_id: Some(rec.execution_id),
                head_hash: expected_prev,
                message: format!(
                    "Hash tamper detected at seq {}: stored {}, recomputed {}",
                    rec.seq, rec.entry_hash, recomputed
                ),
            });
        }

        expected_prev = rec.entry_hash;
    }

    Ok(ChainVerificationReport {
        valid: true,
        total_records,
        broken_at_seq: None,
        broken_execution_id: None,
        head_hash: expected_prev,
        message: format!("Hash chain verified cleanly across {total_records} record(s)"),
    })
}

pub fn verify_sqlite_receipt(db_path: &Path, execution_id: &str) -> Result<ReceiptVerification> {
    let chain_report = verify_sqlite_chain(db_path)?;
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
            "SELECT seq, execution_id, timestamp_utc, tool_name, policy_tier, classification,
                    fuel_consumed, fuel_budget, peak_memory_bytes, duration_ms, code_sha256,
                    prev_hash, entry_hash, summary
             FROM executions
             WHERE execution_id = ?1",
            params![execution_id],
            row_to_record,
        )
        .ok();

    let found = record.is_some();
    let receipt_valid = match (&record, chain_report.broken_at_seq) {
        (Some(rec), None) => {
            let expected = compute_entry_hash(
                &rec.prev_hash,
                &rec.execution_id,
                &rec.timestamp_utc,
                &rec.tool_name,
                &rec.policy_tier,
                &rec.classification,
                rec.fuel_consumed,
                rec.fuel_budget,
                rec.peak_memory_bytes,
                rec.duration_ms,
                &rec.code_sha256,
                &rec.summary,
            );
            rec.entry_hash == expected
        }
        (Some(rec), Some(broken_seq)) => rec.seq < broken_seq,
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
        "SELECT seq, execution_id, timestamp_utc, tool_name, policy_tier, classification,
                fuel_consumed, fuel_budget, peak_memory_bytes, duration_ms, code_sha256,
                prev_hash, entry_hash, summary
         FROM executions
         ORDER BY seq DESC
         LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_record)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
