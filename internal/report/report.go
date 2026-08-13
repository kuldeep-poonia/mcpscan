// Package report handles formatting and rendering scan results to stdout (table or JSON).
package report

import (
	"io"

	"mcpscan/pkg/types"
)

// Standard limitation disclosure notice mandatory on all reports per Section 3.6 of Architecture spec.
const LimitationNotice = `
[NOTICE - KNOWN SCAN LIMITATIONS]
- Stdio Transport Blind Spot: MCPScan detects HTTP-transport MCP servers only.
  Stdio-transport servers (e.g. IDE plugins) are undetectable via network scanning.
- Confidence Model: Discovered servers are labeled with explicit confidence
  levels (confirmed | likely | none).
`

// Reporter manages output formatting for scan results.
type Reporter struct {
	format string
}

// NewReporter constructs a Reporter with specified format ("table" or "json").
func NewReporter(format string) *Reporter {
	return &Reporter{format: format}
}

// Render writes formatted scan results and mandatory limitation disclosure to w.
func (r *Reporter) Render(w io.Writer, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	// Stub implementation for Phase 0 skeleton
	_, err := io.WriteString(w, LimitationNotice+"\nScan complete. 0 servers found (skeleton stub).\n")
	return err
}
