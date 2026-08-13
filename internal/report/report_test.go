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
		ToolVersion:       "v1.0.0-test",
		StartedAt:         time.Now(),
		EndedAt:           time.Now(),
	}

	servers := []types.DiscoveredServer{
		{IP: "127.0.0.1", Port: 8000, MCPConfidence: types.ConfidenceConfirmed, ProtocolVersion: "2024-11-05", AuthStatus: types.AuthUnprotected, RiskLevel: types.RiskHigh},
		{IP: "127.0.0.1", Port: 8001, MCPConfidence: types.ConfidenceLikely, ProtocolVersion: "2024-10-07", AuthStatus: types.AuthProtected, RiskLevel: types.RiskLow},
	}

	err := rep.Render(&buf, record, servers)
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	out := buf.String()

	// Assert mandatory limitation disclosure block
	if !strings.Contains(out, "Stdio Transport Blind Spot") {
		t.Errorf("expected report output to contain limitation notice, got: %s", out)
	}

	// Assert table column headers
	if !strings.Contains(out, "TARGET IP:PORT") || !strings.Contains(out, "MCP CONFIDENCE") || !strings.Contains(out, "AUTH STATUS") {
		t.Errorf("expected report output to contain table headers, got: %s", out)
	}

	// Assert summary line
	if !strings.Contains(out, "Scan complete. 1 MCP server(s) confirmed, 1 likely") {
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
		ToolVersion:       "v1.0.0-test",
	}

	servers := []types.DiscoveredServer{
		{IP: "127.0.0.1", Port: 8000, MCPConfidence: types.ConfidenceConfirmed, ProtocolVersion: "2024-11-05", AuthStatus: types.AuthUnprotected, RiskLevel: types.RiskHigh},
	}

	err := rep.Render(&buf, record, servers)
	if err != nil {
		t.Fatalf("unexpected json render error: %v", err)
	}

	var payload JSONReportPayload
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("failed to unmarshal rendered JSON output: %v", err)
	}

	// Assert limitations block in JSON
	if len(payload.Limitations) == 0 || !strings.Contains(payload.Limitations[0], "Stdio Transport Blind Spot") {
		t.Errorf("expected JSON payload to contain limitations block, got: %+v", payload.Limitations)
	}

	// Assert scan metadata and discovered servers
	if payload.ScanMetadata.ID != 1 || len(payload.DiscoveredServers) != 1 {
		t.Errorf("JSON metadata or server array mismatch: %+v", payload)
	}
}
