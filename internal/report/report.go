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

// Standard limitation disclosure notice mandatory on all reports per Architecture spec.
const LimitationNotice = `
[NOTICE - KNOWN SCAN LIMITATIONS]
- Transport Modes: MCPScan audits HTTP network transports and local AI tool stdio configs.
- Registry Scope: Stdio inspection checks 4 known AI tools (Claude Desktop, Cursor, Antigravity, VS Code); no filesystem-wide search.
- Verification Status: Some platform config paths (Cursor, macOS/Linux variants) are inferred from convention and pending community confirmation.
- Process Matching: OS process cross-referencing is heuristic/best-effort (non-elevated read-only inspection).
- Credential Security: Zero environment secrets are stored or logged; CLI arguments are masked.
- Confidence Model: Discovered servers are labeled with explicit confidence levels (confirmed | likely | unverifiable).
`

// JSONReportPayload represents the structured output for `--format json`.
type JSONReportPayload struct {
	Limitations       []string                     `json:"known_limitations"`
	ScanMetadata      *types.ScanRecord            `json:"scan_metadata"`
	Summary           types.SummaryCounts          `json:"summary"`
	DiscoveredServers []types.DiscoveredServer     `json:"discovered_servers"`
	StdioServers      []types.StdioDiscoveredServer `json:"stdio_servers,omitempty"`
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
func (r *Reporter) Render(w io.Writer, record *types.ScanRecord, httpServers []types.DiscoveredServer, stdioServers []types.StdioDiscoveredServer) error {
	if r.format == "json" {
		return r.renderJSON(w, record, httpServers, stdioServers)
	}
	return r.renderTable(w, record, httpServers, stdioServers)
}

// renderTable renders ASCII tabular output with mandatory limitation disclosure.
func (r *Reporter) renderTable(w io.Writer, record *types.ScanRecord, httpServers []types.DiscoveredServer, stdioServers []types.StdioDiscoveredServer) error {
	// Print mandatory limitation disclosure
	if _, err := io.WriteString(w, LimitationNotice+"\n"); err != nil {
		return err
	}

	c := types.CalculateSummaryCounts(httpServers, stdioServers)

	// 1. Render HTTP Discovered Servers table (if any)
	if len(httpServers) > 0 {
		fmt.Fprintln(w, "DISCOVERED HTTP MCP SERVERS:")
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "TARGET IP:PORT\tMCP CONFIDENCE\tPROTOCOL VERSION\tAUTH STATUS\tRISK LEVEL")
		fmt.Fprintln(tw, "--------------\t--------------\t----------------\t-----------\t----------")

		for _, srv := range httpServers {
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

	// 2. Render Stdio Discovered Servers table (if any)
	if len(stdioServers) > 0 {
		fmt.Fprintln(w, "STDIO-TRANSPORT MCP SERVERS (LOCAL CONFIGS):")
		tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
		fmt.Fprintln(tw, "AI TOOL\tSERVER NAME\tCOMMAND\tARGS SUMMARY\tCONFIDENCE\tPROCESS MATCH\tHAS ENV")
		fmt.Fprintln(tw, "-------\t-----------\t-------\t------------\t----------\t-------------\t-------")

		for _, srv := range stdioServers {
			procMatchStr := "No"
			if srv.ProcessMatchFound {
				if srv.MatchedPID > 0 {
					procMatchStr = fmt.Sprintf("Yes (PID %d)", srv.MatchedPID)
				} else {
					procMatchStr = "Yes"
				}
			}

			hasEnvStr := "No"
			if srv.HasEnvBlock {
				hasEnvStr = "Yes"
			}

			argsDisplay := srv.ArgsSummary
			if len(argsDisplay) > 40 {
				argsDisplay = argsDisplay[:37] + "..."
			}
			if argsDisplay == "" {
				argsDisplay = "-"
			}

			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				srv.SourceTool,
				srv.ServerName,
				srv.Command,
				argsDisplay,
				srv.MCPConfidence,
				procMatchStr,
				hasEnvStr,
			)
		}
		_ = tw.Flush()
		fmt.Fprintln(w, "")
	}

	// 3. Render unified summary line
	var summary string
	if c.Evaluated == 0 {
		summary = fmt.Sprintf("Scan complete. HTTP: %d confirmed, %d likely, %d unverifiable, %d non-MCP.",
			c.Confirmed, c.Likely, c.Unverifiable, c.None)
	} else {
		protectedStr := formatProtectedSummary(c.Protected, c.ProtectedLowRisk, c.ProtectedMediumRisk)
		summary = fmt.Sprintf("Scan complete. HTTP Confidence: %d confirmed, %d likely, %d unverifiable, %d non-MCP. Auth Status: %d unprotected (%d HIGH risk), %s, %d unknown.",
			c.Confirmed, c.Likely, c.Unverifiable, c.None, c.Unprotected, c.HighRisk, protectedStr, c.Unknown)
	}

	if c.StdioTotal > 0 {
		summary += fmt.Sprintf(" Stdio: %d confirmed (active process), %d likely (dormant).",
			c.StdioConfirmed, c.StdioLikely)
	}
	summary += "\n"

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
func (r *Reporter) renderJSON(w io.Writer, record *types.ScanRecord, httpServers []types.DiscoveredServer, stdioServers []types.StdioDiscoveredServer) error {
	if httpServers == nil {
		httpServers = []types.DiscoveredServer{}
	}
	if stdioServers == nil {
		stdioServers = []types.StdioDiscoveredServer{}
	}

	c := types.CalculateSummaryCounts(httpServers, stdioServers)

	payload := JSONReportPayload{
		Limitations: []string{
			"Transport Modes: MCPScan audits HTTP network transports and local AI tool stdio configs.",
			"Registry Scope: Stdio inspection checks 4 known AI tools (Claude Desktop, Cursor, Antigravity, VS Code); no filesystem-wide search.",
			"Verification Status: Some platform config paths (Cursor, macOS/Linux variants) are inferred from convention and pending community confirmation.",
			"Process Matching: OS process cross-referencing is heuristic/best-effort (non-elevated read-only inspection).",
			"Credential Security: Zero environment secrets are stored or logged; CLI arguments are masked.",
			"Confidence Model: Discovered servers are labeled with explicit confidence levels (confirmed | likely | unverifiable).",
		},
		ScanMetadata:      record,
		Summary:           c,
		DiscoveredServers: httpServers,
		StdioServers:      stdioServers,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

