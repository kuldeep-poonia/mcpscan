# MCPScan

**Local-only Shadow MCP Server Discovery & Auth Audit Tool**

MCPScan is a single-binary, offline, zero-telemetry CLI tool designed to scan a local machine or private network range (CIDR) to discover running Model Context Protocol (MCP) servers, verify them, and audit whether authentication is enforced.

> [!IMPORTANT]
> **Privacy Guarantee:** MCPScan makes zero outbound network calls except to user-specified scan targets. No analytics, no telemetry, no phone-home of any kind.

---

## Features

### Network Discovery
- **CIDR & IP Target Resolution:** Scans CIDR ranges (e.g. `192.168.1.0/24`) or explicit IP lists.
- **Safety Host Capping:** Enforces a default cap of 1024 hosts to prevent accidental wide-area scans.
- **RFC1918 Private Range Protection:** Restricts scanning to loopback (`127.0.0.0/8`) and private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) by default. Public IP scanning requires the `--i-understand-the-risk` override flag.
- **Flexible Port Specification:** Supports default port lists, custom ranges, discrete port lists, or exhaustive full-range port scans (`1-65535`).
- **Worker-Pool Concurrency & Global Rate Limiting:** Bounded concurrency pool (`--concurrency`, default 100) and global request rate limiting (`--rate-limit`, default 500 req/sec) to protect target networks from flooding.
- **TCP Connect Scanner:** Standard TCP socket scanner requiring no root or administrator privileges.

### MCP Server Detection
- **Multi-Layer HTTP Verification:** Evaluates services through a 3-layer handshake (Layer 1 JSON-RPC 2.0 structure, Layer 2 MCP `protocolVersion`/`capabilities` validation, Layer 3 secondary method cross-confirmation).
- **Explicit Non-MCP Classification:** Services failing protocol checks (such as Ethereum nodes or plain web servers) are explicitly classified as `none` rather than silently dropped.
- **Resilience Controls:** Defends against memory bombs (1MB response size cap) and hanging connection timeouts.

### Authentication Auditing
- **Single-Request Discipline:** Sends **exactly 1 unauthenticated request** per detected server. No retries, no password lists, no brute-forcing, no auth bypass attempts.
- **Non-Destructive Audit:** Evaluates authentication enforcement without modifying target server state.

### Local Storage & Reporting
- **Embedded SQLite Persistence:** Stores scan records and server details locally in an embedded SQLite database (`scans` and `discovered_servers` schema).
- **Cross-Platform Permission Hardening:** Restricts database file permissions (`0600` on Unix; Windows ACL inheritance stripping via `icacls`).
- **Multi-Format Output:** Formats reports as clean ASCII tables (`--format table`) or structured JSON (`--format json`).
- **Offline Report Inspection:** Re-render stored scan results anytime via `mcpscan report --db <path.db> [--format table|json]`.

---

## Installation

### Downloading Pre-Built Binaries

Pre-compiled, zero-CGO binaries are available on the [GitHub Releases](https://github.com/kuldeep-poonia/mcpscan/releases/tag/v1.0.0) page:

- **Linux (x86_64):** `mcpscan-linux-amd64`
- **macOS (Intel):** `mcpscan-darwin-amd64`
- **macOS (Apple Silicon):** `mcpscan-darwin-arm64`
- **Windows (x86_64):** `mcpscan-windows-amd64.exe`

### Verifying SHA256 Checksums

Download `checksums.txt` along with your binary and verify its integrity:

```bash
# Linux / macOS
sha256sum -c checksums.txt --ignore-missing

# Windows (PowerShell)
Get-FileHash mcpscan-windows-amd64.exe -Algorithm SHA256
```

### Building from Source

```bash
git clone https://github.com/kuldeep-poonia/mcpscan.git
cd mcpscan
go build -o mcpscan main.go
```

---

## Step-by-Step Usage Guide

### 1. Default Quick Scan (Common Ports)
If you omit the `--ports` flag, MCPScan automatically scans popular MCP development ports (`8000`, `8080`, `3000`, `5000`, `8081`, `8001`, `8002`, `8888`, `9000`, `9090`, `5001`, `8443`):

```bash
mcpscan scan --local
```

### 2. Scanning Specific Ports or Ranges
To scan specific ports or custom port ranges, use the `--ports` flag:

```bash
# Scan specific discrete ports
mcpscan scan --local --ports 8001,8002,9000

# Scan a range of ports
mcpscan scan --local --ports 8000-8500

# Combine discrete ports and ranges
mcpscan scan --local --ports 3000,5000,8000-8050
```

### 3. Exhaustive Full Machine Scan (All 65,535 Ports)
To perform a complete scan across **all 65,535 TCP ports** on your machine:

```bash
mcpscan scan --local --ports 1-65535
```

### 4. Scanning a Network Subnet (Private Range / CIDR)
To scan an entire local network subnet or range of hosts:

```bash
# Scan a /24 subnet (up to 256 hosts) with custom rate limit
mcpscan scan --target 192.168.1.0/24 --concurrency 50 --rate-limit 200 --output corp_scan.db
```

### 5. Exporting Structured JSON Output
To export results directly in JSON format for SIEM or automated security tool integration:

```bash
mcpscan scan --target 10.0.0.0/28 --format json --output audit.db
```

### 6. Offline Report Inspection Subcommand
Re-render previously saved SQLite database scan records anytime without re-scanning the network:

```bash
# Display formatted summary table from database
mcpscan report --db corp_scan.db --format table

# Display raw JSON report from database
mcpscan report --db audit.db --format json
```

---

## CLI Flag Reference

| Flag | Default | Description |
|---|---|---|
| `--target` | `127.0.0.1` | Target IP address or CIDR subnet (e.g. `192.168.1.0/24`). |
| `--local` | `false` | Quick flag alias to target `127.0.0.1`. |
| `--ports` | *Common MCP ports* | Port specification: list (`8000,8080`), range (`8000-8500`), or full (`1-65535`). |
| `--concurrency` | `100` | Worker pool concurrency count (max `500`). |
| `--rate-limit` | `500` | Global request rate limit in req/sec (max `2000`). |
| `--timeout` | `2s` | Network socket dial and HTTP context timeout duration. |
| `--output` | `mcpscan.db` | Path to local SQLite database file for persisting scan results. |
| `--format` | `table` | Output display format (`table` or `json`). |
| `--i-understand-the-risk` | `false` | Override flag required to enable scanning public IP addresses. |
| `--db` | `mcpscan.db` | Database file path for `mcpscan report` subcommand. |

---

## Understanding the Output

### MCP Confidence Levels
- **`confirmed`:** Server passed all 3 verification layers (valid JSON-RPC 2.0, MCP capabilities/protocolVersion, and secondary probe).
- **`likely`:** Server passed Layer 1 & Layer 2 checks.
- **`none`:** Service did not respond with valid MCP JSON-RPC protocol fields (e.g. Ethereum RPC nodes, plain web servers).

### Authentication Status & Risk Levels
- **`unprotected` / `HIGH` Risk:** Server responded with a full tool list to unauthenticated requests. Immediate security attention required.
- **`protected` / `LOW` Risk:** Server returned HTTP 401 Unauthorized or 403 Forbidden to unauthenticated requests. Authentication is enforced.
- **`unknown` / `MEDIUM` Risk:** Server returned an ambiguous response or a network timeout occurred during probing.

---

## Known Limitations

- **Stdio Transport Blind Spot:** MCPScan detects HTTP-transport MCP servers only. Stdio-transport servers (e.g., inside IDE plugins) are undetectable via network scanning.
- **Confidence Model:** Discovered services are labeled with explicit confidence levels (`confirmed`, `likely`, `none`) rather than absolute assumptions.

---

## Contributing & Building from Source

Requirements: Go 1.21 or later.

```bash
# Run unit tests
go test -v ./...

# Cross-compile release binaries
make cross-build
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
