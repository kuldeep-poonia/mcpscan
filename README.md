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
- **Port Range Specification:** Flexible port range and list parsing (e.g. `--ports 8000-8005,3000,5000,8080`).
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

## Usage

### Scenario 1: Quick Scan of Localhost
```bash
mcpscan scan --local --ports 8000-8500
```

### Scenario 2: Scanning a Corporate Private Network Range
```bash
mcpscan scan --target 192.168.1.0/24 --concurrency 50 --rate-limit 200 --output corp_scan.db
```

### Scenario 3: Exporting JSON Output for SIEM / Security Tool Integration
```bash
mcpscan scan --target 10.0.0.0/28 --format json --output audit.db
```

### Scenario 4: Re-rendering Stored Scan Results Offline
```bash
mcpscan report --db corp_scan.db --format table
mcpscan report --db audit.db --format json
```

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
