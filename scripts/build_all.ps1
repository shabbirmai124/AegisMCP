$ErrorActionPreference = "Stop"
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --manifest-path crates/aegis-guest-js/Cargo.toml --release
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p aegis-host
cargo test --workspace -- --nocapture
./target/release/aegis-mcp.exe precompile
./target/release/aegis-mcp.exe doctor
