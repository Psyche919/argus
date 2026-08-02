# Argus

**See what your tokens are hiding.**

Argus is an open-source JWT (JSON Web Token) security analysis toolkit written in Rust. It decodes tokens, runs security checks against known JWT vulnerability classes, optionally verifies signatures, and produces professional reports in multiple formats — built for pentesters and security engineers auditing JWT-based authentication.

Argus is an **analysis and auditing tool**, not an exploitation framework.

[![CI](https://github.com/Psyche919/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/Psyche919/argus/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

## Features

- **Structural decoding** — permissively decodes any JWT, including intentionally malformed or insecure tokens (e.g. `alg: none`)
- **Security checks** — detects common JWT vulnerabilities and misconfigurations:
  - `alg-none` — unsigned tokens claiming `alg: none`
  - `header-shape` — malformed or non-standard headers
  - `missing-exp` / `expired` — expiration hygiene issues
  - `nbf-future` / `iat-future` — timing anomalies suggesting tampering or clock skew
  - `sensitive-data-exposure` — sensitive data placed in the (unencrypted) payload
  - `excessive-lifetime` — unusually long-lived tokens
- **Signature verification** — optional HMAC (HS256/384/512) and RSA (RS256/384/512) verification against a supplied key
- **Risk scoring** — overall severity plus a full findings breakdown
- **Configurable** — enable/disable individual checks via `argus.toml`
- **Multiple report formats** — terminal, JSON, Markdown, and HTML
- **Batch mode** — analyze many tokens from a file or stdin in one pass

## Installation

Requires [Rust](https://rustup.rs/) (stable toolchain).

```bash
git clone https://github.com/Psyche919/argus.git
cd argus
cargo build --release
```

The compiled binary will be at `target/release/argus`. To install it onto your `PATH`:

```bash
cargo install --path .
```

## Quick Start

Decode a token:

```bash
argus decode <token>
```

Analyze a token for security issues:

```bash
argus analyze <token>
```

Analyze with signature verification:

```bash
argus analyze <token> --secret "your-hmac-secret"
argus analyze <token> --public-key path/to/public.pem
```

Analyze many tokens at once:

```bash
argus batch --file tokens.txt
cat tokens.txt | argus batch
```

Generate an HTML report:

```bash
argus analyze <token> --format html -o report.html
```

## CLI Reference

### `argus decode <token>`

Decodes a JWT and prints its header and payload as JSON. No analysis performed.

### `argus analyze <token> [OPTIONS]`

Runs the full analysis pipeline: decode, security checks, risk scoring, and optional verification.

| Flag | Description |
|---|---|
| `--format <terminal\|json\|markdown\|html>` | Output format (default: `terminal`) |
| `-o, --output <path>` | Write output to a file instead of stdout |
| `--secret <string>` | HMAC secret for signature verification |
| `--secret-file <path>` | Path to a file containing the HMAC secret |
| `--public-key <path>` | Path to a PEM-encoded RSA public key |

`--secret`, `--secret-file`, and `--public-key` are mutually exclusive.

### `argus batch [OPTIONS]`

Analyzes multiple tokens from a file (`--file`, one token per line) or stdin. Accepts the same `--format`, `-o`, and key-source flags as `analyze`, applied uniformly to every token.

## Configuration

Argus reads an optional `argus.toml` file from the current working directory:

```toml
disabled_checks = ["missing-exp", "excessive-lifetime"]
```

If no config file is present, all checks run with default settings.

## Architecture

Argus is structured as a library crate (`src/lib.rs`) with a thin CLI binary (`src/main.rs`) on top, so the core analysis engine is independently usable and testable.

```text
src/
├── token.rs — permissive JWT decoding
├── checks/ — individual security checks (Check trait, one file per check)
├── scoring.rs — risk aggregation
├── verify.rs — HMAC/RSA signature verification
├── config.rs — argus.toml resolution
├── report.rs — Report data structure
└── report/render/ — output renderers (terminal, JSON, Markdown, HTML)
```

Each check implements a shared `Check` trait and is independently registered — adding a new check never requires modifying existing ones. Each renderer implements a shared `Renderer` trait operating on `&[Report]`, which is why batch mode required no renderer changes at all.

## Security Considerations

- Argus performs **structural analysis only** unless a key is explicitly supplied for verification — it does not attempt to guess, brute-force, or fetch keys.
- Secret material passed via `--secret` may be visible in shell history; prefer `--secret-file` for sensitive secrets.
- Argus does not fetch JWKS URLs or make any network requests.

## Known Limitations

- ECDSA (ES256/384/512) verification is not yet supported.
- JWKS (JSON Web Key Set) fetching is not yet supported — keys must be supplied locally.
- Batch mode applies one key uniformly to all tokens in a batch; per-token keys are not supported.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache License, Version 2.0](LICENSE-APACHE) at your option.

## Contributing

Contributions are welcome. By submitting a pull request, you agree your contribution is licensed under the same MIT/Apache-2.0 dual license as the project.