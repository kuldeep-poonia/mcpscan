# MCPScan

**Local-only Shadow MCP Server Discovery & Auth Audit Tool**

MCPScan is a single-binary, offline, zero-telemetry CLI tool designed to scan a local machine or private network range (CIDR) to discover running Model Context Protocol (MCP) servers, verify them, and audit whether authentication is enforced.

> [!IMPORTANT]
> **Privacy Guarantee:** MCPScan makes zero outbound network calls except to user-specified scan targets. No analytics, no phone-home, no telemetry.

---

## Capabilities & Scope (v1)

- **Target Scanning:** Localhost and RFC1918 private network CIDR scanning.
- **MCP Detection:** Multi-layer verification of HTTP-transport MCP servers.
- **Auth Audit:** Non-destructive single-probe evaluation of authentication status.
- **Local Storage:** Embedded SQLite persistence.
- **CLI Reports:** Output in clean tabular or structured JSON format.

---

## Known Blind Spots & Limitations

- **Stdio Transport:** MCPScan currently detects HTTP-transport MCP servers only. Stdio-transport servers (e.g., inside IDE plugins) are undetectable via network scanning.
- **Detection Confidence:** Discovered services are classified with explicit confidence levels (`confirmed`, `likely`, `none`) rather than absolute assumptions.

---

## Getting Started

### Prerequisites
- Go 1.21 or later

### Building from Source

```bash
go build -o mcpscan main.go
```

### Usage

```bash
# Print help
./mcpscan --help

# Display version
./mcpscan --version
```
