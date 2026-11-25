use crate::audit::{AuditLedger, AuditRecordInput, sha256_hex};
use crate::config::AegisConfig;
use crate::engine::AegisEngine;
use crate::error::AegisError;
use crate::policy::{PolicyTier, SandboxPolicy};
use crate::sandbox::{ExecutionOutcome, run_isolated_js, run_wasm_bytes};
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
    /// Optional JSON value exposed to the script as global `INPUT`.
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    /// Policy tier: pure_compute (default), scoped_scratchpad, readonly_data, or allowlisted_net.
    #[serde(default)]
    pub tier: Option<PolicyTier>,
    /// Optional map of relative filenames to UTF-8 contents seeded into /workspace (scoped_scratchpad tier only).
    #[serde(default)]
    pub files: Option<HashMap<String, String>>,
    /// Optional host directory to mount read-only at /data (readonly_data tier only; must be inside readonly_roots).
    #[serde(default)]
    pub readonly_dir: Option<String>,
    /// Optional caller RAM limit in MiB (may only tighten below the tier ceiling).
    #[serde(default)]
    pub memory_mb: Option<u64>,
    /// Optional caller instruction fuel budget (may only tighten below the tier ceiling).
    #[serde(default)]
    pub fuel_budget: Option<u64>,
    /// Optional allowlisted HTTPS URL fetched by the host SSRF-guarded proxy (allowlisted_net tier only).
    #[serde(default)]
    pub fetch_url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteWasmParams {
    /// Base64-encoded WebAssembly binary (.wasm) targeting WASI preview1.
    #[serde(default)]
    pub wasm_base64: Option<String>,
    /// Optional named plugin configured under [plugins] in aegis.toml.
    #[serde(default)]
    pub plugin_name: Option<String>,
    /// Optional UTF-8 stdin payload passed to the WASI module.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Policy tier: pure_compute (default), scoped_scratchpad, readonly_data, or allowlisted_net.
    #[serde(default)]
    pub tier: Option<PolicyTier>,
    /// Optional host directory to mount read-only at /data (readonly_data tier only).
    #[serde(default)]
    pub readonly_dir: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectPolicyParams {
    /// Optional policy tier to inspect; if omitted returns all configured tiers and cache stats.
    #[serde(default)]
    pub tier: Option<PolicyTier>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyReceiptParams {
    /// UUID run_id returned by a previous sandbox execution.
    pub run_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListExecutionsParams {
    /// Maximum number of recent audit records to return (default 20, max 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Serialize)]
struct ExecutionToolPayload {
    run_id: String,
    ok: bool,
    status: String,
    classification: String,
    tier: PolicyTier,
    result: Option<serde_json::Value>,
    console_logs: Vec<String>,
    stdout: String,
    stderr: String,
    truncated_output: bool,
    trap_reason: Option<String>,
    diagnostic: Option<serde_json::Value>,
    fuel_consumed: u64,
    fuel_budget: u64,
    peak_memory_bytes: usize,
    duration_us: u64,
    cache_hit: bool,
    scratchpad_files_written: Vec<String>,
    receipt_sha256: String,
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
        input_sha256: String,
        outcome: ExecutionOutcome,
        include_raw_stdout: bool,
    ) -> Result<CallToolResult, McpError> {
        let classification_str = format!("{:?}", outcome.classification);
        let output_digest_src = if let Some(res) = &outcome.parsed_result {
            serde_json::to_string(res).unwrap_or_default()
        } else if !outcome.stdout.is_empty() {
            outcome.stdout.clone()
        } else {
            outcome.trap_reason.clone().unwrap_or_default()
        };
        let output_sha256 = sha256_hex(output_digest_src.as_bytes());

        let receipt = self
            .ledger
            .record(AuditRecordInput {
                run_id: outcome.run_id.clone(),
                tool_name: tool_name.to_string(),
                tier: outcome.tier.as_str().to_string(),
                input_sha256,
                output_sha256,
                fuel_consumed: outcome.fuel_consumed,
                fuel_budget: outcome.fuel_budget,
                peak_memory_bytes: outcome.peak_memory_bytes,
                duration_us: outcome.duration_us,
                cache_hit: outcome.cache_hit,
                status: outcome.status.clone(),
                trap_reason: outcome.trap_reason.clone(),
            })
            .await
            .map_err(|e| {
                let err = AegisError::AuditError(format!("Audit write failed: {e}"));
                McpError::internal_error(err.to_string(), None)
            })?;

        let payload = ExecutionToolPayload {
            run_id: outcome.run_id,
            ok: outcome.ok,
            status: outcome.status,
            classification: classification_str,
            tier: outcome.tier,
            result: outcome.parsed_result,
            console_logs: outcome.console_logs,
            stdout: if include_raw_stdout {
                outcome.stdout
            } else {
                String::new()
            },
            stderr: outcome.stderr,
            truncated_output: outcome.truncated_output,
            trap_reason: outcome.trap_reason,
            diagnostic: outcome.diagnostic,
            fuel_consumed: outcome.fuel_consumed,
            fuel_budget: outcome.fuel_budget,
            peak_memory_bytes: outcome.peak_memory_bytes,
            duration_us: outcome.duration_us,
            cache_hit: outcome.cache_hit,
            scratchpad_files_written: outcome.scratchpad_files_written,
            receipt_sha256: receipt.receipt_hash,
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
        let tier = params.tier.unwrap_or(PolicyTier::PureCompute);
        let base_policy = SandboxPolicy::from_config(&self.config, tier);
        let policy = match base_policy.with_overrides(params.memory_mb, params.fuel_budget) {
            Ok(p) => p,
            Err(err) => {
                let text = serde_json::to_string_pretty(&err.to_llm_diagnostic())
                    .unwrap_or_else(|_| err.to_string());
                return Ok(CallToolResult::error(vec![ContentBlock::text(text)]));
            }
        };

        let ro_path = params.readonly_dir.as_deref().map(PathBuf::from);
        let input_sha256 = sha256_hex(params.code.as_bytes());

        let outcome = run_isolated_js(
            &self.engine,
            &self.config,
            &policy,
            &params.code,
            params.input.unwrap_or(serde_json::Value::Null),
            params.files,
            ro_path.as_deref(),
            params.fetch_url.as_deref(),
        )
        .await;

        self.record_and_format("execute_isolated_js", input_sha256, outcome, false)
            .await
    }

    #[tool(
        name = "execute_wasm_binary",
        description = "Execute a base64-encoded WASI preview1 .wasm binary or a named plugin from aegis.toml inside a zero-trust micro-sandbox with capability tier enforcement and a SHA-256 audit receipt."
    )]
    async fn execute_wasm_binary(
        &self,
        Parameters(params): Parameters<ExecuteWasmParams>,
    ) -> Result<CallToolResult, McpError> {
        let (artifact_name, wasm_bytes) = if let Some(plugin_name) = params.plugin_name {
            let plugin_path = self.config.plugins.get(&plugin_name).ok_or_else(|| {
                McpError::invalid_params(
                    format!("Unknown plugin '{plugin_name}' not configured in aegis.toml [plugins]"),
                    None,
                )
            })?;
            let bytes = std::fs::read(plugin_path).map_err(|e| {
                McpError::internal_error(
                    format!(
                        "Failed reading plugin '{}' at {}: {e}",
                        plugin_name,
                        plugin_path.display()
                    ),
                    None,
                )
            })?;
            (plugin_name, bytes)
        } else if let Some(b64) = params.wasm_base64 {
            let bytes = BASE64.decode(b64.trim()).map_err(|e| {
                McpError::invalid_params(format!("Invalid base64 Wasm payload: {e}"), None)
            })?;
            ("inline_wasm".to_string(), bytes)
        } else {
            return Err(McpError::invalid_params(
                "Provide either 'wasm_base64' or 'plugin_name'",
                None,
            ));
        };

        let tier = params.tier.unwrap_or(PolicyTier::PureCompute);
        let policy = SandboxPolicy::from_config(&self.config, tier);
        let ro_path = params.readonly_dir.as_deref().map(PathBuf::from);
        let stdin_bytes = params.stdin.unwrap_or_default().into_bytes();
        let input_sha256 = sha256_hex(&wasm_bytes);

        let outcome = run_wasm_bytes(
            &self.engine,
            &policy,
            &artifact_name,
            &wasm_bytes,
            &stdin_bytes,
            ro_path.as_deref(),
        )
        .await;

        self.record_and_format("execute_wasm_binary", input_sha256, outcome, true)
            .await
    }

    #[tool(
        name = "inspect_sandbox_policy",
        description = "Inspect active zero-trust capability tiers, RAM caps, fuel budgets, epoch deadlines, readonly roots, SSRF domain allowlists, plugins, and AOT .cwasm cache stats."
    )]
    async fn inspect_sandbox_policy(
        &self,
        Parameters(params): Parameters<InspectPolicyParams>,
    ) -> Result<CallToolResult, McpError> {
        let tiers_json = if let Some(tier) = params.tier {
            serde_json::to_value(SandboxPolicy::from_config(&self.config, tier))
        } else {
            serde_json::to_value(vec![
                SandboxPolicy::from_config(&self.config, PolicyTier::PureCompute),
                SandboxPolicy::from_config(&self.config, PolicyTier::ScopedScratchpad),
                SandboxPolicy::from_config(&self.config, PolicyTier::ReadonlyData),
                SandboxPolicy::from_config(&self.config, PolicyTier::AllowlistedNet),
            ])
        }
        .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        let response = serde_json::json!({
            "tiers": tiers_json,
            "readonly_roots": self.config.tiers.readonly_data.readonly_roots,
            "allowed_domains": self.config.tiers.allowlisted_net.allowed_domains,
            "plugins": self.config.plugins.keys().collect::<Vec<_>>(),
            "cache_stats": self.engine.cache_stats(),
        });

        let json_text = serde_json::to_string_pretty(&response)
            .map_err(|e| McpError::internal_error(format!("JSON encode error: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(json_text)]))
    }

    #[tool(
        name = "verify_execution_receipt",
        description = "Cryptographically verify a run_id execution receipt and the full SHA-256 hash chain in the SQLite audit ledger."
    )]
    async fn verify_execution_receipt(
        &self,
        Parameters(params): Parameters<VerifyReceiptParams>,
    ) -> Result<CallToolResult, McpError> {
        let verification = self
            .ledger
            .verify_receipt(&params.run_id)
            .map_err(|e| {
                let err = AegisError::AuditError(format!("Ledger verification failed: {e}"));
                McpError::internal_error(err.to_string(), None)
            })?;

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
        let records = self.ledger.recent(limit).map_err(|e| {
            let err = AegisError::AuditError(format!("Ledger query failed: {e}"));
            McpError::internal_error(err.to_string(), None)
        })?;
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
