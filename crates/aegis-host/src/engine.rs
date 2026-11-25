use crate::config::AegisConfig;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio_util::sync::CancellationToken;
use wasmtime::{Config, Engine, Module};

#[derive(Debug, Clone)]
pub struct PrecompileReport {
    pub cwasm_path: PathBuf,
    pub size_bytes: u64,
    pub cache_hit: bool,
}

pub struct AegisEngine {
    pub engine: Engine,
    cache_dir: PathBuf,
    epoch_tick_ms: u64,
    fuel_yield_interval: u64,
    modules: RwLock<HashMap<String, Arc<Module>>>,
}

impl AegisEngine {
    pub fn initialize(cfg: &AegisConfig) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| anyhow::anyhow!("{e:#}"))?;
        std::fs::create_dir_all(&cfg.engine.cache_dir)?;

        Ok(Self {
            engine,
            cache_dir: cfg.engine.cache_dir.clone(),
            epoch_tick_ms: cfg.engine.epoch_tick_ms,
            fuel_yield_interval: cfg.engine.fuel_yield_interval,
            modules: RwLock::new(HashMap::new()),
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

    fn cache_key_for_bytes(wasm_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(wasm_bytes);
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        hasher.update(std::env::consts::ARCH.as_bytes());
        hasher.update(std::env::consts::OS.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn precompile_wasm_file(&self, wasm_path: &Path, force: bool) -> Result<PrecompileReport> {
        let bytes = std::fs::read(wasm_path)
            .with_context(|| format!("Missing Wasm artifact at {}", wasm_path.display()))?;
        let key = Self::cache_key_for_bytes(&bytes);
        let cwasm_path = self.cache_dir.join(format!("{key}.cwasm"));

        if !force && cwasm_path.exists() {
            let size_bytes = std::fs::metadata(&cwasm_path)?.len();
            return Ok(PrecompileReport {
                cwasm_path,
                size_bytes,
                cache_hit: true,
            });
        }

        let module = Module::new(&self.engine, &bytes)
            .map_err(|e| anyhow::anyhow!("Failed to compile {}: {e:#}", wasm_path.display()))?;
        let serialized = module.serialize().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let tmp_path = self.cache_dir.join(format!("{key}.cwasm.tmp"));
        std::fs::write(&tmp_path, &serialized)?;
        std::fs::rename(&tmp_path, &cwasm_path)?;

        let arc_mod = Arc::new(module);
        self.modules
            .write()
            .expect("module cache lock poisoned")
            .insert(key, arc_mod);

        Ok(PrecompileReport {
            cwasm_path,
            size_bytes: serialized.len() as u64,
            cache_hit: false,
        })
    }

    pub fn load_or_compile_bytes(&self, wasm_bytes: &[u8]) -> Result<(Arc<Module>, bool)> {
        let key = Self::cache_key_for_bytes(wasm_bytes);
        if let Some(cached) = self
            .modules
            .read()
            .expect("module cache lock poisoned")
            .get(&key)
        {
            return Ok((cached.clone(), true));
        }

        let cwasm_path = self.cache_dir.join(format!("{key}.cwasm"));
        let (module, hit) = if cwasm_path.exists() {
            // SAFETY: cwasm artifacts are keyed by SHA-256 of bytecode + crate version + target triple.
            match unsafe { Module::deserialize_file(&self.engine, &cwasm_path) } {
                Ok(m) => (Arc::new(m), true),
                Err(_) => {
                    let m = Module::new(&self.engine, wasm_bytes)
                        .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                    let tmp = self.cache_dir.join(format!("{key}.cwasm.tmp"));
                    std::fs::write(&tmp, m.serialize().map_err(|e| anyhow::anyhow!("{e:#}"))?)?;
                    std::fs::rename(&tmp, &cwasm_path)?;
                    (Arc::new(m), false)
                }
            }
        } else {
            let m = Module::new(&self.engine, wasm_bytes)
                .map_err(|e| anyhow::anyhow!("{e:#}"))?;
            let tmp = self.cache_dir.join(format!("{key}.cwasm.tmp"));
            std::fs::write(&tmp, m.serialize().map_err(|e| anyhow::anyhow!("{e:#}"))?)?;
            std::fs::rename(&tmp, &cwasm_path)?;
            (Arc::new(m), false)
        };

        self.modules
            .write()
            .expect("module cache lock poisoned")
            .insert(key, module.clone());
        Ok((module, hit))
    }
}
