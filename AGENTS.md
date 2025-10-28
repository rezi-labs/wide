# AGENTS.md - Development Guide for WIDE

## Build Commands
- **Run**: `just run` or `cargo run`
- **Test**: `just test` or `cargo test` (run single test: `cargo test test_name`)
- **Lint**: `just lint` (runs fmt check + clippy)
- **Format**: `just fmt` (formats code and applies fixes)
- **Watch**: `just watch` (auto-restart on changes)
- **Verify**: `just verify` (runs lint + test) - **ALWAYS run this before considering work complete**

## Code Style Guidelines
- **Formatting**: Use `cargo fmt` - follows Rust standard formatting
- **Imports**: Group by std, external crates, then local modules
- **Types**: Use explicit types for public APIs, inference for locals
- **Naming**: snake_case for variables/functions, PascalCase for types
- **Error Handling**: Use `anyhow::Result` for main functions, `?` operator for propagation
- **Async**: Use `tokio` runtime, prefer `async/await` over futures combinators
- **Structs**: Use `#[derive(Clone)]` when needed, prefer owned data
- **Config**: Use `serde` with snake_case fields, provide defaults with `#[serde(default)]`

## Workflow Rules
- **Always run `just verify`** before considering any task complete
- If `just verify` fails, fix issues with `just fmt` for formatting or address test/clippy errors
- Do not commit or mark work complete until `just verify` passes clean

## Project Structure
- Single binary crate: reverse proxy with Let's Encrypt support
- Configuration via `proxy.yaml` file with domain routing
- Certificate management with ACME protocol and self-signed fallback