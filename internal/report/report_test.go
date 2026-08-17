package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

func TestReport_TableFormat(t *testing.T) {
	rep := NewReporter("table")
	var buf bytes.Buffer

	record := &types.ScanRecord{
		ID:                1,
		TargetRange:       "127.0.0.1",
		TotalHostsScanned: 1,
		ToolVersion:       "v2.0.0-test",
		StartedAt:         time.Now(),
		EndedAt:           time.Now(),
	}

	httpServers := []types.DiscoveredServer{
		{IP: "127.0.0.1", Port: 8000, MCPConfidence: types.ConfidenceConfirmed, ProtocolVersion: "2024-11-05", AuthStatus: types.AuthUnprotected, RiskLevel: types.RiskHigh},
		{IP: "127.0.0.1", Port: 8001, MCPConfidence: types.ConfidenceLikely, ProtocolVersion: "2024-10-07", AuthStatus: types.AuthProtected, RiskLevel: types.RiskLow},
	}

	stdioServers := []types.StdioDiscoveredServer{
		{
			SourceTool:        "Claude Desktop",
			ConfigFile:        "/Users/test/claude_desktop_config.json",
			ServerName:        "filesystem",
			Command:           "npx",
			ArgsSummary:       "-y @modelcontextprotocol/server-filesystem",
			HasEnvBlock:       false,
			MCPConfidence:     types.ConfidenceLikely,
			ProcessMatchFound: false,
		},
		{
			SourceTool:        "Cursor",
			ConfigFile:        "/Users/test/.cursor/mcp.json",
			ServerName:        "github",
			Command:           "node",
			ArgsSummary:       "/opt/mcp/github.js",
			HasEnvBlock:       true,
			MCPConfidence:     types.ConfidenceConfirmed,
			ProcessMatchFound: true,
			MatchedPID:        1234,
		},
	}

	err := rep.Render(&buf, record, httpServers, stdioServers)
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	out := buf.String()

	// Assert mandatory limitation disclosure block
	if !strings.Contains(out, "Transport Modes") || !strings.Contains(out, "Credential Security") || !strings.Contains(out, "Transport Security") {
		t.Errorf("expected report output to contain limitation notice, got: %s", out)
	}
	if !strings.Contains(out, "HTTP Confidence Levels: confirmed | likely | unverifiable_protected | none") {
		t.Errorf("expected HTTP confidence levels in notice, got: %s", out)
	}
	if !strings.Contains(out, "Stdio Confidence Levels: confirmed (active process) | likely (configured, dormant)") {
		t.Errorf("expected Stdio confidence levels in notice, got: %s", out)
	}

	// Assert HTTP table column headers
	if !strings.Contains(out, "DISCOVERED HTTP MCP SERVERS:") || !strings.Contains(out, "TARGET IP:PORT") || !strings.Contains(out, "TRANSPORT SECURITY") {
		t.Errorf("expected report output to contain HTTP table headers, got: %s", out)
	}

	// Assert Stdio table column headers
	if !strings.Contains(out, "STDIO-TRANSPORT MCP SERVERS (LOCAL CONFIGS):") || !strings.Contains(out, "AI TOOL") || !strings.Contains(out, "PROCESS MATCH") {
		t.Errorf("expected report output to contain Stdio table headers, got: %s", out)
	}

	// Assert Stdio table contents
	if !strings.Contains(out, "Claude Desktop") || !strings.Contains(out, "Yes (PID 1234)") {
		t.Errorf("expected Stdio server details in table, got: %s", out)
	}

	// Assert unified summary line
	if !strings.Contains(out, "Scan complete.") || !strings.Contains(out, "Stdio: 1 confirmed (active process), 1 likely (dormant).") {
		t.Errorf("expected summary line in report, got: %s", out)
	}
}

func TestReport_JSONFormat(t *testing.T) {
	rep := NewReporter("json")
	var buf bytes.Buffer

	record := &types.ScanRecord{
		ID:                1,
		TargetRange:       "127.0.0.1",
		TotalHostsScanned: 1,
		ToolVersion:       "v2.0.0-test",
	}

	httpServers := []types.DiscoveredServer{
		{IP: "127.0.0.1", Port: 8000, MCPConfidence: types.ConfidenceConfirmed, ProtocolVersion: "2024-11-05", AuthStatus: types.AuthUnprotected, RiskLevel: types.RiskHigh},
	}

	stdioServers := []types.StdioDiscoveredServer{
		{
			SourceTool:        "Claude Desktop",
			ServerName:        "filesystem",
			MCPConfidence:     types.ConfidenceConfirmed,
			ProcessMatchFound: true,
			MatchedPID:        999,
		},
	}

	err := rep.Render(&buf, record, httpServers, stdioServers)
	if err != nil {
		t.Fatalf("unexpected json render error: %v", err)
	}

	var payload JSONReportPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("failed to unmarshal rendered JSON output: %v", err)
	}

	// Assert limitations block in JSON
	if len(payload.Limitations) == 0 || !strings.Contains(payload.Limitations[0], "Transport Modes") {
		t.Errorf("expected JSON payload to contain limitations block, got: %+v", payload.Limitations)
	}

	// Assert scan metadata and discovered servers
	if payload.ScanMetadata.ID != 1 || len(payload.DiscoveredServers) != 1 || len(payload.StdioServers) != 1 {
		t.Errorf("JSON metadata or server array mismatch: %+v", payload)
	}

	// Assert summary counts in JSON
	if payload.Summary.Confirmed != 1 || payload.Summary.StdioConfirmed != 1 {
		t.Errorf("JSON summary counts mismatch: %+v", payload.Summary)
	}
}

