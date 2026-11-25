use crate::config::{AegisConfig, DEFAULT_FUEL_YIELD_INTERVAL};
use crate::error::AegisError;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio_util::sync::CancellationToken;
use wasmtime::{Config, Engine, Module};

#[derive(Debug, Clone, Serialize)]
pub struct PrecompileReport {
    pub artifact_name: String,
    pub cwasm_path: PathBuf,
    pub sha256_path: PathBuf,
    pub cwasm_sha256: String,
    pub size_bytes: u64,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub cache_dir: PathBuf,
    pub precompiled_artifacts: usize,
    pub in_memory_modules: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub hit_rate_pct: f64,
}

pub struct AegisEngine {
    pub engine: Arc<Engine>,
    cache_dir: PathBuf,
    epoch_tick_ms: u64,
    fuel_yield_interval: u64,
    modules: RwLock<HashMap<String, Arc<Module>>>,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sanitize_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if clean.is_empty() {
        "module".to_string()
    } else {
        clean
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AegisError> {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let tmp_path = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp_path, bytes)
        .map_err(|e| AegisError::EngineError(format!("Failed writing {}: {e}", tmp_path.display())))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| AegisError::EngineError(format!("Failed renaming {}: {e}", path.display())))?;
    Ok(())
}

impl AegisEngine {
    pub fn initialize(cfg: &AegisConfig) -> Result<Self, AegisError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config)
            .map_err(|e| AegisError::EngineError(format!("Wasmtime Engine init failed: {e:#}")))?;
        std::fs::create_dir_all(&cfg.server.cache_dir).map_err(|e| {
            AegisError::EngineError(format!(
                "Failed creating cache dir {}: {e}",
                cfg.server.cache_dir.display()
            ))
        })?;

        Ok(Self {
            engine: Arc::new(engine),
            cache_dir: cfg.server.cache_dir.clone(),
            epoch_tick_ms: cfg.server.epoch_tick_ms,
            fuel_yield_interval: DEFAULT_FUEL_YIELD_INTERVAL,
            modules: RwLock::new(HashMap::new()),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
        })
    }

    pub fn fuel_yield_interval(&self) -> u64 {
        self.fuel_yield_interval
    }

    pub fn spawn_epoch_ticker(&self) -> CancellationToken {
        let engine = self.engine.clone();
        let interval_ms = self.epoch_tick_ms;
        let token = CancellationToken::new();
        let child = token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            loop {
                tokio::select! {
                    _ = child.cancelled() => break,
                    _ = ticker.tick() => engine.increment_epoch(),
                }
            }
        });
        token
    }

    pub fn cache_key_for_bytes(wasm_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(wasm_bytes);
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        hasher.update(std::env::consts::OS.as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn cache_paths(&self, name: &str, key: &str) -> (PathBuf, PathBuf) {
        let prefix = sanitize_name(name);
        let cwasm_path = self.cache_dir.join(format!("{prefix}-{key}.cwasm"));
        let sha256_path = self.cache_dir.join(format!("{prefix}-{key}.cwasm.sha256"));
        (cwasm_path, sha256_path)
    }

    fn verify_and_deserialize(
        &self,
        cwasm_path: &Path,
        sha256_path: &Path,
    ) -> Result<(Module, String), AegisError> {
        if !cwasm_path.exists() || !sha256_path.exists() {
            return Err(AegisError::CacheIntegrityError(format!(
                "Missing .cwasm or .sha256 sidecar at {}",
                cwasm_path.display()
            )));
        }

        let expected_hash = std::fs::read_to_string(sha256_path)
            .map_err(|e| {
                AegisError::CacheIntegrityError(format!(
                    "Failed reading sidecar {}: {e}",
                    sha256_path.display()
                ))
            })?
            .trim()
            .to_lowercase();

        let disk_bytes = std::fs::read(cwasm_path).map_err(|e| {
            AegisError::CacheIntegrityError(format!(
                "Failed reading cwasm {}: {e}",
                cwasm_path.display()
            ))
        })?;
        let actual_hash = sha256_hex(&disk_bytes);
        if actual_hash != expected_hash {
            return Err(AegisError::CacheIntegrityError(format!(
                "SHA-256 mismatch for {}: expected {expected_hash}, got {actual_hash}",
                cwasm_path.display()
            )));
        }

        // SAFETY: We just verified the exact SHA-256 digest of the precompiled artifact on disk
        // against its content-addressed sidecar keyed by wasm bytecode + pkg version + OS + arch.
        let module = unsafe { Module::deserialize_file(&self.engine, cwasm_path) }.map_err(|e| {
            AegisError::CacheIntegrityError(format!(
                "Failed deserializing verified cwasm {}: {e:#}",
                cwasm_path.display()
            ))
        })?;
        Ok((module, actual_hash))
    }

    fn compile_and_persist(
        &self,
        name: &str,
        wasm_bytes: &[u8],
        key: &str,
    ) -> Result<(Arc<Module>, PathBuf, PathBuf, String, u64), AegisError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AegisError::EngineError(format!("Failed to compile '{name}': {e:#}")))?;
        let serialized = module
            .serialize()
            .map_err(|e| AegisError::EngineError(format!("Failed to serialize '{name}': {e:#}")))?;
        let cwasm_sha256 = sha256_hex(&serialized);
        let (cwasm_path, sha256_path) = self.cache_paths(name, key);
        atomic_write(&cwasm_path, &serialized)?;
        atomic_write(&sha256_path, cwasm_sha256.as_bytes())?;

        let arc_mod = Arc::new(module);
        self.modules
            .write()
            .expect("module cache lock poisoned")
            .insert(key.to_string(), arc_mod.clone());

        Ok((
            arc_mod,
            cwasm_path,
            sha256_path,
            cwasm_sha256,
            serialized.len() as u64,
        ))
    }

    pub fn precompile_wasm_file(
        &self,
        wasm_path: &Path,
        force: bool,
    ) -> Result<PrecompileReport, AegisError> {
        let bytes = std::fs::read(wasm_path).map_err(|e| {
            AegisError::ModuleNotFound(format!(
                "Missing Wasm artifact at {}: {e}",
                wasm_path.display()
            ))
        })?;
        let name = wasm_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("guest");
        let key = Self::cache_key_for_bytes(&bytes);
        let (cwasm_path, sha256_path) = self.cache_paths(name, &key);

        if !force
            && let Ok((module, cwasm_sha256)) = self.verify_and_deserialize(&cwasm_path, &sha256_path)
        {
            let size_bytes = std::fs::metadata(&cwasm_path).map(|m| m.len()).unwrap_or(0);
            self.modules
                .write()
                .expect("module cache lock poisoned")
                .insert(key, Arc::new(module));
            return Ok(PrecompileReport {
                artifact_name: name.to_string(),
                cwasm_path,
                sha256_path,
                cwasm_sha256,
                size_bytes,
                cache_hit: true,
            });
        }

        let (_arc_mod, cwasm_path, sha256_path, cwasm_sha256, size_bytes) =
            self.compile_and_persist(name, &bytes, &key)?;

        Ok(PrecompileReport {
            artifact_name: name.to_string(),
            cwasm_path,
            sha256_path,
            cwasm_sha256,
            size_bytes,
            cache_hit: false,
        })
    }

    pub fn load_or_compile_bytes(
        &self,
        artifact_name: &str,
        wasm_bytes: &[u8],
    ) -> Result<(Arc<Module>, bool), AegisError> {
        let key = Self::cache_key_for_bytes(wasm_bytes);
        if let Some(cached) = self
            .modules
            .read()
            .expect("module cache lock poisoned")
            .get(&key)
        {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok((cached.clone(), true));
        }

        let (cwasm_path, sha256_path) = self.cache_paths(artifact_name, &key);
        match self.verify_and_deserialize(&cwasm_path, &sha256_path) {
            Ok((module, _)) => {
                let arc_mod = Arc::new(module);
                self.modules
                    .write()
                    .expect("module cache lock poisoned")
                    .insert(key, arc_mod.clone());
                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                Ok((arc_mod, true))
            }
            Err(err) => {
                if cwasm_path.exists() {
                    tracing::warn!(
                        "AOT cache integrity check failed for {}; recompiling: {err}",
                        cwasm_path.display()
                    );
                }
                let (arc_mod, _, _, _, _) = self.compile_and_persist(artifact_name, wasm_bytes, &key)?;
                self.cache_misses.fetch_add(1, Ordering::Relaxed);
                Ok((arc_mod, false))
            }
        }
    }

    pub fn cache_stats(&self) -> CacheStats {
        let precompiled_artifacts = std::fs::read_dir(&self.cache_dir)
            .ok()
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("cwasm"))
                    .count()
            })
            .unwrap_or(0);
        let in_memory_modules = self
            .modules
            .read()
            .expect("module cache lock poisoned")
            .len();
        let cache_hits = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.cache_misses.load(Ordering::Relaxed);
        let total = cache_hits + cache_misses;
        let hit_rate_pct = if total == 0 {
            0.0
        } else {
            (cache_hits as f64 / total as f64) * 100.0
        };
        CacheStats {
            cache_dir: self.cache_dir.clone(),
            precompiled_artifacts,
            in_memory_modules,
            cache_hits,
            cache_misses,
            hit_rate_pct,
        }
    }
}
