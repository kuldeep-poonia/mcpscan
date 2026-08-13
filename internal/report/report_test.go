package report

import (
	"bytes"
	"strings"
	"testing"

	"mcpscan/pkg/types"
)

func TestRender(t *testing.T) {
	rep := NewReporter("table")
	var buf bytes.Buffer
	servers := []types.DiscoveredServer{
		{IP: "127.0.0.1", Port: 8000, MCPConfidence: types.ConfidenceConfirmed, AuthStatus: types.AuthUnprotected},
		{IP: "127.0.0.1", Port: 8001, MCPConfidence: types.ConfidenceLikely, AuthStatus: types.AuthProtected},
	}

	err := rep.Render(&buf, &types.ScanRecord{}, servers)
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Stdio Transport Blind Spot") {
		t.Errorf("expected report output to contain limitation notice, got: %s", out)
	}

	if !strings.Contains(out, "Scan complete. 1 MCP server(s) confirmed, 1 likely.") {
		t.Errorf("expected clean summary in report, got: %s", out)
	}
}
