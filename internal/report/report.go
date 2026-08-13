// Package report handles formatting and rendering scan results to stdout (table or JSON).
package report

import (
	"fmt"
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
	var confirmed, likely, unprotected, protected int
	for _, s := range servers {
		if s.MCPConfidence == types.ConfidenceConfirmed {
			confirmed++
		} else if s.MCPConfidence == types.ConfidenceLikely {
			likely++
		}

		if s.AuthStatus == types.AuthUnprotected {
			unprotected++
		} else if s.AuthStatus == types.AuthProtected {
			protected++
		}
	}

	summary := fmt.Sprintf("Scan complete. %d MCP server(s) confirmed, %d likely.\n", confirmed, likely)
	_, err := io.WriteString(w, LimitationNotice+"\n"+summary)
	return err
}
