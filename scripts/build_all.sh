#!/usr/bin/env bash
set -euo pipefail

rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p aegis-host
cargo test --workspace -- --nocapture
./target/release/aegis-mcp precompile
./target/release/aegis-mcp doctor
