#!/usr/bin/env bash
set -euo pipefail

rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release
cargo clippy --manifest-path crates/aegis-host/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path crates/aegis-host/Cargo.toml --release
cargo test --manifest-path crates/aegis-host/Cargo.toml -- --nocapture
./target/release/aegis-mcp precompile --config aegis.toml
./target/release/aegis-mcp doctor --config aegis.toml
