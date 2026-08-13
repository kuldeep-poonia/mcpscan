# MCPScan

**Local-only Shadow MCP Server Discovery & Auth Audit Tool**

MCPScan is a single-binary, offline, zero-telemetry CLI tool designed to scan a local machine or private network range (CIDR) to discover running Model Context Protocol (MCP) servers, verify them, and audit whether authentication is enforced.

> [!IMPORTANT]
> **Privacy Guarantee:** MCPScan makes zero outbound network calls except to user-specified scan targets. No analytics, no phone-home, no telemetry.

---

## Features Implemented

### Phase 1 — Target Resolver & Worker-Pool Port Scanner
- **CIDR & Single IP Expansion:** Converts CIDRs (e.g. `192.168.1.0/24`) or IP lists into bounded target host lists.
- **Safety Host Capping:** Enforces a default limit of 1024 hosts to prevent accidental wide-area scans.
- **RFC1918 Private Range Protection:** Restricts scanning to loopback (`127.0.0.0/8`) and private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) by default. Public IP scanning requires explicit `--i-understand-the-risk` override flag.
- **Port Specification Parsing:** Flexible port lists and range parsing (e.g. `--ports 8000-8005,3000,5000,8080`).
- **Worker-Pool Concurrency:** Configurable worker pool (`--concurrency`, default 100).
- **Single Shared Rate Limiting:** Global rate limit ticker (`--rate-limit`, default 500 req/sec) shared across all worker goroutines to protect target networks from flooding.
- **TCP Connect Scanner:** Non-elevated, standard TCP `net.DialTimeout` scanner.

---

## Usage Examples

### Scanning Localhost
```bash
mcpscan scan --local --ports 8000-8500
```

### Scanning a Private Network CIDR
```bash
mcpscan scan --target 192.168.1.0/24 --concurrency 50 --rate-limit 200
```

### Advanced Port Ranges & Custom Timeout
```bash
mcpscan scan --target 10.0.0.15 --ports 3000,5000,8000-8080 --timeout 1s
```

---

## Known Blind Spots & Limitations

- **Stdio Transport:** MCPScan currently detects HTTP-transport MCP servers only. Stdio-transport servers (e.g., inside IDE plugins) are undetectable via network scanning.
- **Detection Confidence:** Discovered services are classified with explicit confidence levels (`confirmed`, `likely`, `none`) rather than absolute assumptions.

---

## Building & Testing

```bash
# Run unit tests (with race detector)
go test -v -race ./...

# Build binary
go build -o mcpscan main.go
```
