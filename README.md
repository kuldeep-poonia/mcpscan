# MCPScan

[![Go Version](https://img.shields.io/github/go-mod/go-version/kuldeep-poonia/mcpscan?style=flat-square&color=00ADD8)](https://go.dev/)
[![Latest Release](https://img.shields.io/github/v/release/kuldeep-poonia/mcpscan?style=flat-square&color=green)](https://github.com/kuldeep-poonia/mcpscan/releases)
[![License: MIT](https://img.shields.io/github/license/kuldeep-poonia/mcpscan?style=flat-square&color=blue)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/kuldeep-poonia/mcpscan?style=flat-square&color=yellow)](https://github.com/kuldeep-poonia/mcpscan/stargazers)

**Local-only Shadow MCP Server Discovery & Auth Audit Tool**

MCPScan is a single-binary, offline, zero-telemetry CLI tool designed to discover and audit Model Context Protocol (MCP) servers across your private network (HTTP transports) and local AI developer tools (Stdio transports).

> [!IMPORTANT]
> **Privacy Guarantee:** MCPScan makes zero outbound telemetry calls. For local stdio configs, environment variable contents (`env` blocks) are **never stored or displayed** (only their presence is noted), and all inline credentials in CLI arguments are masked before persistence.

---

## Features

### Network Discovery (HTTP Transport)
- **CIDR & IP Target Resolution:** Scans CIDR ranges (e.g. `192.168.1.0/24`) or explicit IP lists.
- **Safety Host Capping:** Enforces a default cap of 1024 hosts to prevent accidental wide-area scans.
- **RFC1918 Private Range Protection:** Restricts scanning to loopback (`127.0.0.0/8`) and private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) by default. Public IP scanning requires the `--i-understand-the-risk` override flag.
- **Worker-Pool Concurrency & Global Rate Limiting:** Bounded concurrency pool (`--concurrency`, default 100) and global request rate limiting (`--rate-limit`, default 500 req/sec) to protect target networks.
- **3-Layer HTTP Verification:** Evaluates services through JSON-RPC 2.0 structure, MCP `protocolVersion`/`capabilities` validation, and secondary method verification.
- **Transport Security Check:** Identifies whether HTTP endpoints operate over `plaintext HTTP` or encrypted `HTTPS` (TLS presence), surfacing wire-interception risk independently of auth status.
- **Parameter-Shape Danger Detection:** Passively inspects tool parameter schemas (`inputSchema`) during Layer 3 verification to flag unconstrained string parameters matching high-risk system terms (`command`, `path`, `sql`, `script`), closing the evasion gap of innocuously-named tools without external LLMs.
- **Tool-Definition Integrity Check (Rug-Pull Detection):** Computes deterministic SHA-256 digests over canonicalized tool definitions and tracks changes across scans. Distinguishes tool mutations (`modified`) from endpoint port-reuse (`replaced`) using handshake identity correlation.
- **Single-Request Auth Audit:** Sends **exactly 1 unauthenticated request** per detected HTTP server to audit authentication enforcement without brute-forcing or state alteration.

### Local AI Tool Discovery (Stdio Transport — Opt-in)
- **Opt-in Stdio Detection:** Enabled via `--include-stdio` to inspect local AI tool configurations.
- **Known AI Tool Registry:** Checks known configuration paths for **Claude Desktop**, **Cursor**, **Antigravity (Gemini IDE)**, and **VS Code**. No blind filesystem-wide crawling.
- **3-Layer Stdio Verification:**
  - **Layer 1:** JSON syntax validity (guarded with a 5MB read limit).
  - **Layer 2:** Schema structural validation (`mcpServers` object with `command`; `serverUrl` entries are excluded to prevent double-counting).
  - **Layer 3:** Non-elevated OS process cross-referencing (matches running processes via Windows CIM, Linux `/proc`, or macOS `ps` to upgrade from `likely` to `confirmed`).
- **Stdio Configuration Integrity:** Computes canonical SHA-256 hashes of execution parameters (`command`, `args`, `has_env_block`) to track config changes across scans (`new`, `unchanged`, `modified`).
- **Two-Layer Credential Masking:** Sensitive CLI flags, HTTP headers (`Header: Value`), and high-entropy secret tokens embedded in commands/args are partially masked (`sk-...789`), while structured filesystem paths are preserved.
- **Zero `env` Storage:** Records only `has_env_block: true` when environment variables are present — secret keys and values inside `env` blocks are never read, stored, or displayed.

### Local Storage & Reporting
- **Embedded SQLite Persistence:** Stores scan records, HTTP servers (`discovered_servers`), and stdio servers (`stdio_discovered_servers`) with foreign key cascade deletion.
- **Cross-Platform Permission Hardening:** Restricts database file permissions (`0600` on Unix; Windows ACL inheritance stripping via `icacls`).
- **Multi-Format Output:** Formats reports as clean ASCII tables (`--format table`) or structured JSON (`--format json`).
- **Offline Report Inspection:** Re-render stored scan results anytime via `mcpscan report --db <path.db> [--format table|json]`.

---

## Installation

### Downloading Pre-Built Binaries

Pre-compiled, zero-CGO binaries are available on the [GitHub Releases](https://github.com/kuldeep-poonia/mcpscan/releases) page:

- **Linux (x86_64):** `mcpscan-linux-amd64`
- **macOS (Intel):** `mcpscan-darwin-amd64`
- **macOS (Apple Silicon):** `mcpscan-darwin-arm64`
- **Windows (x86_64):** `mcpscan-windows-amd64.exe`

### Building from Source

```bash
git clone https://github.com/kuldeep-poonia/mcpscan.git
cd mcpscan
go build -o mcpscan main.go
```

---

## Usage Guide

### 1. Default Network Scan (HTTP Transport)
Scan common local MCP HTTP ports (`8000`, `8080`, `3000`, `5000`, `8081`, `8001`, `8002`, `8888`, `9000`, `9090`):

```bash
mcpscan scan --local
```

### 2. Full Local Scan (HTTP + Local AI Stdio Configs)
Discover both network-exposed HTTP MCP servers and local AI tool stdio configs:

```bash
mcpscan scan --local --include-stdio
```

### 3. Scanning a Network Subnet (Private CIDR)
Scan an entire subnet for unauthorized shadow MCP servers:

```bash
mcpscan scan --target 192.168.1.0/24 --concurrency 50 --rate-limit 200 --output corp_scan.db
```

### 4. Exporting Structured JSON Output
Export full structured telemetry for SIEM and security pipelines:

```bash
mcpscan scan --local --include-stdio --format json --output audit.db
```

### 5. Offline Report Inspection Subcommand
Re-render previously saved SQLite database reports anytime:

```bash
# Display formatted ASCII table from database
mcpscan report --db audit.db --format table

# Display raw JSON report from database
mcpscan report --db audit.db --format json
```

---

## CLI Flag Reference

| Flag | Default | Description |
|---|---|---|
| `--target` | `127.0.0.1` | Target IP address or CIDR subnet (e.g. `192.168.1.0/24`). |
| `--local` | `false` | Quick flag alias to target `127.0.0.1`. |
| `--include-stdio` | `false` | Discover local stdio-transport MCP servers from AI tool configs. |
| `--ports` | *Common ports* | Port specification: list (`8000,8080`), range (`8000-8500`), or full (`1-65535`). |
| `--concurrency` | `100` | Worker pool concurrency count (max `500`). |
| `--rate-limit` | `500` | Global request rate limit in req/sec (max `2000`). |
| `--timeout` | `2s` | Network socket dial and HTTP context timeout duration. |
| `--output` | `mcpscan.db` | Path to local SQLite database file for persisting scan results. |
| `--format` | `table` | Output display format (`table` or `json`). |
| `--i-understand-the-risk` | `false` | Override flag required to enable scanning public IP addresses. |
| `--db` | `mcpscan.db` | Database file path for `mcpscan report` subcommand. |

---

## Understanding Confidence & Auth Taxonomies

### HTTP Confidence Levels
- **`confirmed`:** Server passed all 3 verification layers (JSON-RPC 2.0, MCP capabilities, secondary probe).
- **`likely`:** Server passed Layer 1 & Layer 2 checks.
- **`unverifiable_protected`:** Server returned HTTP 401/403 with `WWW-Authenticate` or JSON body on initial handshake. Authentication prevents probing internal MCP capabilities.
- **`none`:** Service did not respond with valid MCP protocol fields (e.g. Ethereum nodes, plain web servers).

### Stdio Confidence Levels
- **`confirmed`:** Configured stdio server matches an active running OS process with aligned arguments.
- **`likely`:** Structurally valid stdio server configuration found in an AI tool config, but currently dormant (no matching running process).

### Authentication Status & Risk Levels (HTTP)
- **`unprotected` / `HIGH` Risk:** Server responded with a full tool list to unauthenticated requests. Immediate remediation required.
- **`protected` / `LOW` Risk:** Server returned HTTP 401 Unauthorized or 403 Forbidden to unauthenticated requests.
- **`unknown` / `MEDIUM` Risk:** Server returned an ambiguous response or timed out during probing.

### Tool & Config Integrity Levels
- **`new`:** First observation of the server endpoint or stdio tool configuration.
- **`unchanged`:** Canonical SHA-256 hash matches the previous scan record.
- **`modified`:** Tool definitions (HTTP) or execution parameters (stdio) altered since last observation.
- **`replaced` (HTTP only):** A different server was detected on the same IP:port endpoint (port reuse disambiguation via `serverInfo.name`). Stdio configs match by exact `source_tool:server_name:config_file` keys where port reuse does not apply.
- **`not evaluated`:** Tool definitions were unreachable during scan (`unverifiable_protected` or non-MCP).

---

## Known Limitations & Scope Disclosure

- **Transport Scope:** Stdio detection checks 4 known AI tools (Claude Desktop, Cursor, Antigravity, VS Code); it does not perform blind filesystem-wide searches.
- **Transport Security:** HTTPS detection verifies the presence of TLS wire encryption only; it does not validate certificate authority chains or trust status (allowing audit of internal/self-signed private services). Plaintext exposure on loopback (`127.0.0.1`) represents a lower exposure profile than plaintext on routable subnets.
- **Detection Latency:** For an individual unresponsive server (hanging without dropping the connection), worst-case detection time can take up to 2x the configured `--timeout` due to sequential HTTP-then-HTTPS probing.
- **Parameter Danger Scope:** Checks parameter names and unconstrained string types against a maintained system-access dictionary (`command`, `path`, `sql`, etc.) alongside a false-positive deny-list (`zip_code`, `status_code`, etc.). Non-standard compound identifiers not yet included on the deny-list may trigger false positives; this operates as a local syntactic and type heuristic without semantic LLM analysis.
- **Integrity Check Baseline:** Cross-scan comparison relies on historical records persisted in the target SQLite database file. Scanning with a newly created database file establishes a fresh baseline (`new`).
- **Path Verification:** Some platform configuration paths (Cursor across OSs, and macOS/Linux variants) are inferred from convention and pending community verification. *If a config path differs for your environment, please open a GitHub issue with your tool and OS path details.*
- **Process Matching:** Process cross-referencing uses non-elevated OS inspection and is best-effort/heuristic.
- **Zero Credential Exposure:** Secret keys in CLI arguments are masked, and environment variables are never stored or logged.

---

## Contributing & Building from Source

Requirements: Go 1.21 or later.

```bash
# Run unit tests
go test -v ./...

# Build local binary
go build -o mcpscan main.go
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

