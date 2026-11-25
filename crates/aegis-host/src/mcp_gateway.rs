use crate::audit::{AuditLedger, AuditRecordInput, sha256_hex};
use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::policy::{PolicyTier, SandboxPolicy};
use crate::sandbox::{SandboxOutcome, run_isolated_js, run_wasm_bytes};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig,
};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteJsParams {
    /// JavaScript source code to evaluate inside the isolated WASI micro-sandbox.
    pub code: String,
    /// Policy tier: pure_compute (default), scoped_scratchpad, readonly_data, or allowlisted_net.
    #[serde(default)]
    pub policy_tier: Option<PolicyTier>,
    /// Optional JSON value exposed to the script as global `input`.
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    /// Optional map of relative filenames to UTF-8 contents seeded into /workspace (scoped_scratchpad tier only).
    #[serde(default)]
    pub scratchpad_files: Option<HashMap<String, String>>,
    /// Optional host directory to mount read-only at /data (readonly_data tier only; must be inside readonly_roots).
    #[serde(default)]
    pub readonly_mount_path: Option<String>,
    /// Optional allowlisted HTTPS URL fetched by the host SSRF-guarded proxy and injected into `input.fetched_body` (allowlisted_net tier only).
    #[serde(default)]
    pub fetch_url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteWasmParams {
    /// Base64-encoded WebAssembly binary (.wasm) targeting WASI preview1.
    pub wasm_base64: String,
    /// Optional UTF-8 stdin payload passed to the WASI module.
    #[serde(default)]
    pub stdin_utf8: Option<String>,
    /// Policy tier: pure_compute (default), scoped_scratchpad, readonly_data, or allowlisted_net.
    #[serde(default)]
    pub policy_tier: Option<PolicyTier>,
    /// Optional host directory to mount read-only at /data (readonly_data tier only).
    #[serde(default)]
    pub readonly_mount_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectPolicyParams {
    /// Policy tier to inspect; if omitted returns all configured tiers.
    #[serde(default)]
    pub policy_tier: Option<PolicyTier>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyReceiptParams {
    /// UUID execution_id returned by a previous sandbox execution.
    pub execution_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListExecutionsParams {
    /// Maximum number of recent audit records to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Serialize)]
struct ExecutionToolPayload {
    execution_id: String,
    ok: bool,
    classification: String,
    policy_tier: PolicyTier,
    result: Option<serde_json::Value>,
    console_logs: Vec<String>,
    stdout: String,
    stderr: String,
    error: Option<String>,
    fuel_consumed: u64,
    fuel_budget: u64,
    peak_memory_bytes: usize,
    duration_ms: u64,
    wasm_cold_compile: bool,
    scratchpad_files_written: Vec<String>,
    receipt_hash: String,
    prev_hash: String,
}

#[derive(Clone)]
pub struct AegisMcpServer {
    config: Arc<AegisConfig>,
    engine: Arc<AegisEngine>,
    ledger: AuditLedger,
    tool_router: ToolRouter<Self>,
}

impl AegisMcpServer {
    pub fn new(config: Arc<AegisConfig>, engine: Arc<AegisEngine>, ledger: AuditLedger) -> Self {
        Self {
            config,
            engine,
            ledger,
            tool_router: Self::tool_router(),
        }
    }

    async fn record_and_format(
        &self,
        tool_name: &str,
        code_hash: String,
        outcome: SandboxOutcome,
        include_raw_stdout: bool,
    ) -> Result<CallToolResult, McpError> {
        let classification_str = format!("{:?}", outcome.classification);
        let tier_str = serde_json::to_value(outcome.policy_tier)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "pure_compute".to_string());

        let summary = if let Some(err) = &outcome.error {
            err.chars().take(180).collect()
        } else if let Some(res) = &outcome.parsed_result {
            serde_json::to_string(res)
                .unwrap_or_default()
                .chars()
                .take(180)
                .collect()
        } else {
            outcome.stdout.chars().take(180).collect()
        };

        let receipt = self
            .ledger
            .record(AuditRecordInput {
                execution_id: outcome.execution_id.clone(),
                tool_name: tool_name.to_string(),
                policy_tier: tier_str,
                classification: classification_str.clone(),
                fuel_consumed: outcome.fuel_consumed,
                fuel_budget: outcome.fuel_budget,
                peak_memory_bytes: outcome.peak_memory_bytes,
                duration_ms: outcome.duration_ms,
                code_sha256: code_hash,
                summary,
            })
            .await
            .map_err(|e| McpError::internal_error(format!("Audit write failed: {e}"), None))?;

        let payload = ExecutionToolPayload {
            execution_id: outcome.execution_id,
            ok: outcome.ok,
            classification: classification_str,
            policy_tier: outcome.policy_tier,
            result: outcome.parsed_result,
            console_logs: outcome.console_logs,
            stdout: if include_raw_stdout {
                outcome.stdout
            } else {
                String::new()
            },
            stderr: outcome.stderr,
            error: outcome.error,
            fuel_consumed: outcome.fuel_consumed,
            fuel_budget: outcome.fuel_budget,
            peak_memory_bytes: outcome.peak_memory_bytes,
            duration_ms: outcome.duration_ms,
            wasm_cold_compile: outcome.wasm_cold_compile,
            scratchpad_files_written: outcome.scratchpad_files_written,
            receipt_hash: receipt.entry_hash,
            prev_hash: receipt.prev_hash,
        };

        let json_text = serde_json::to_string_pretty(&payload)
            .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        if payload.ok {
            Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]))
        } else {
            Ok(CallToolResult::error(vec![ContentBlock::text(json_text)]))
        }
    }
}

#[tool_router]
impl AegisMcpServer {
    #[tool(
        name = "execute_isolated_js",
        description = "Execute untrusted JavaScript inside an isolated zero-trust WASI micro-sandbox with strict fuel, wall-clock epoch, and RAM limits, returning structured JSON and a SHA-256 audit receipt."
    )]
    async fn execute_isolated_js(
        &self,
        Parameters(params): Parameters<ExecuteJsParams>,
    ) -> Result<CallToolResult, McpError> {
        let tier = params.policy_tier.unwrap_or(PolicyTier::PureCompute);
        let policy = SandboxPolicy::from_config(&self.config, tier);
        let ro_path = params.readonly_mount_path.as_deref().map(PathBuf::from);
        let code_hash = sha256_hex(params.code.as_bytes());

        let outcome = run_isolated_js(
            &self.engine,
            &self.config,
            &policy,
            &params.code,
            params.input.unwrap_or(serde_json::Value::Null),
            params.scratchpad_files,
            ro_path.as_deref(),
            params.fetch_url.as_deref(),
        )
        .await;

        self.record_and_format("execute_isolated_js", code_hash, outcome, false)
            .await
    }

    #[tool(
        name = "execute_wasm_binary",
        description = "Execute an arbitrary base64-encoded WASI preview1 .wasm binary inside a zero-trust micro-sandbox with capability tier enforcement and a SHA-256 audit receipt."
    )]
    async fn execute_wasm_binary(
        &self,
        Parameters(params): Parameters<ExecuteWasmParams>,
    ) -> Result<CallToolResult, McpError> {
        let wasm_bytes = BASE64
            .decode(params.wasm_base64.trim())
            .map_err(|e| McpError::invalid_params(format!("Invalid base64 Wasm payload: {e}"), None))?;

        let tier = params.policy_tier.unwrap_or(PolicyTier::PureCompute);
        let policy = SandboxPolicy::from_config(&self.config, tier);
        let ro_path = params.readonly_mount_path.as_deref().map(PathBuf::from);
        let stdin_bytes = params.stdin_utf8.unwrap_or_default().into_bytes();
        let code_hash = sha256_hex(&wasm_bytes);

        let outcome = run_wasm_bytes(
            &self.engine,
            &policy,
            &wasm_bytes,
            &stdin_bytes,
            ro_path.as_deref(),
        )
        .await;

        self.record_and_format("execute_wasm_binary", code_hash, outcome, true)
            .await
    }

    #[tool(
        name = "inspect_sandbox_policy",
        description = "Inspect active zero-trust capability tiers, RAM caps, fuel budgets, epoch deadlines, readonly mount roots, and SSRF domain allowlists."
    )]
    async fn inspect_sandbox_policy(
        &self,
        Parameters(params): Parameters<InspectPolicyParams>,
    ) -> Result<CallToolResult, McpError> {
        let json_text = if let Some(tier) = params.policy_tier {
            let policy = SandboxPolicy::from_config(&self.config, tier);
            serde_json::to_string_pretty(&policy)
        } else {
            let all = vec![
                SandboxPolicy::from_config(&self.config, PolicyTier::PureCompute),
                SandboxPolicy::from_config(&self.config, PolicyTier::ScopedScratchpad),
                SandboxPolicy::from_config(&self.config, PolicyTier::ReadonlyData),
                SandboxPolicy::from_config(&self.config, PolicyTier::AllowlistedNet),
            ];
            serde_json::to_string_pretty(&all)
        }
        .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]))
    }

    #[tool(
        name = "verify_execution_receipt",
        description = "Cryptographically verify an execution receipt and the full SHA-256 hash chain in the SQLite audit ledger."
    )]
    async fn verify_execution_receipt(
        &self,
        Parameters(params): Parameters<VerifyReceiptParams>,
    ) -> Result<CallToolResult, McpError> {
        let verification = self
            .ledger
            .verify_receipt(&params.execution_id)
            .map_err(|e| McpError::internal_error(format!("Ledger verification failed: {e}"), None))?;

        let json_text = serde_json::to_string_pretty(&verification)
            .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        if verification.found && verification.receipt_valid && verification.chain_valid {
            Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]))
        } else {
            Ok(CallToolResult::error(vec![ContentBlock::text(json_text)]))
        }
    }

    #[tool(
        name = "list_recent_executions",
        description = "List recent sandboxed executions and security blocks from the immutable hash-chained audit ledger."
    )]
    async fn list_recent_executions(
        &self,
        Parameters(params): Parameters<ListExecutionsParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(20).clamp(1, 100);
        let records = self
            .ledger
            .recent(limit)
            .map_err(|e| McpError::internal_error(format!("Ledger query failed: {e}"), None))?;
        let json_text = serde_json::to_string_pretty(&records)
            .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AegisMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("aegis-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "AegisMCP Zero-Trust WebAssembly Sandbox Server. All untrusted JavaScript and Wasm executes inside isolated WASI micro-sandboxes with deterministic fuel, epoch, RAM, and capability enforcement.",
            )
    }
}

#[cfg(feature = "http")]
pub fn build_streamable_http_service(
    config: Arc<AegisConfig>,
    engine: Arc<AegisEngine>,
    ledger: AuditLedger,
) -> rmcp::transport::streamable_http_server::StreamableHttpService<
    AegisMcpServer,
    rmcp::transport::streamable_http_server::session::local::LocalSessionManager,
> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };
    let factory_cfg = config;
    let factory_eng = engine;
    let factory_ledger = ledger;
    StreamableHttpService::new(
        move || {
            Ok(AegisMcpServer::new(
                factory_cfg.clone(),
                factory_eng.clone(),
                factory_ledger.clone(),
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}
