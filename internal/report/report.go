// Package report handles formatting and rendering scan results to stdout (table or JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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

// JSONReportPayload represents the structured output for `--format json`.
type JSONReportPayload struct {
	Limitations       []string                 `json:"known_limitations"`
	ScanMetadata      *types.ScanRecord        `json:"scan_metadata"`
	DiscoveredServers []types.DiscoveredServer `json:"discovered_servers"`
}

// Reporter manages output formatting for scan results.
type Reporter struct {
	format string
}

// NewReporter constructs a Reporter with specified format ("table" or "json").
func NewReporter(format string) *Reporter {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "json" {
		format = "table"
	}
	return &Reporter{format: format}
}

// Render writes formatted scan results and mandatory limitation disclosure to w.
func (r *Reporter) Render(w io.Writer, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	if r.format == "json" {
		return r.renderJSON(w, record, servers)
	}
	return r.renderTable(w, record, servers)
}

// renderTable renders ASCII tabular output with mandatory limitation disclosure.
func (r *Reporter) renderTable(w io.Writer, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	// Print mandatory limitation disclosure
	if _, err := io.WriteString(w, LimitationNotice+"\n"); err != nil {
		return err
	}

	c := types.CalculateSummaryCounts(servers)

	totalDiscovered := len(servers)
	if totalDiscovered > 0 {
		fmt.Fprintln(w, "DISCOVERED MCP SERVERS:")
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "TARGET IP:PORT\tMCP CONFIDENCE\tPROTOCOL VERSION\tAUTH STATUS\tRISK LEVEL")
		fmt.Fprintln(tw, "--------------\t--------------\t----------------\t-----------\t----------")

		for _, srv := range servers {
			targetAddr := fmt.Sprintf("%s:%d", srv.IP, srv.Port)
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
				targetAddr,
				srv.MCPConfidence,
				srv.ProtocolVersion,
				srv.AuthStatus,
				srv.RiskLevel,
			)
		}
		_ = tw.Flush()
		fmt.Fprintln(w, "")
	}

	var summary string
	if c.Evaluated == 0 {
		summary = "Scan complete. 0 MCP server(s) confirmed, 0 likely, 0 unverifiable.\n"
	} else {
		protectedStr := formatProtectedSummary(c.Protected, c.ProtectedLowRisk, c.ProtectedMediumRisk)
		summary = fmt.Sprintf("Scan complete. %d MCP server(s) confirmed, %d likely, %d unverifiable (%d unprotected [%d HIGH risk], %s).\n",
			c.Confirmed, c.Likely, c.Unverifiable, c.Unprotected, c.HighRisk, protectedStr)
	}

	_, err := io.WriteString(w, summary)
	return err
}

func formatProtectedSummary(total, lowRisk, mediumRisk int) string {
	if total == 0 {
		return "0 protected"
	}
	if lowRisk > 0 && mediumRisk > 0 {
		return fmt.Sprintf("%d protected [%d LOW risk, %d MEDIUM risk]", total, lowRisk, mediumRisk)
	}
	if mediumRisk > 0 {
		return fmt.Sprintf("%d protected [%d MEDIUM risk]", total, mediumRisk)
	}
	return fmt.Sprintf("%d protected [%d LOW risk]", total, lowRisk)
}

// renderJSON renders structured JSON payload containing scan metadata and mandatory limitations.
func (r *Reporter) renderJSON(w io.Writer, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	if servers == nil {
		servers = []types.DiscoveredServer{}
	}

	payload := JSONReportPayload{
		Limitations: []string{
			"Stdio Transport Blind Spot: MCPScan detects HTTP-transport MCP servers only. Stdio-transport servers are undetectable via network scanning.",
			"Confidence Model: Discovered servers are labeled with explicit confidence levels (confirmed | likely | none).",
		},
		ScanMetadata:      record,
		DiscoveredServers: servers,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}
