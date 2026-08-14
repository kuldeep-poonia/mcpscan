package stdioscanner

import (
	"strings"
	"testing"

	"mcpscan/pkg/types"
)

// TestStdioDetector_ThreeLayerVerification tests the complete 3-layer detection pipeline.
func TestStdioDetector_ThreeLayerVerification(t *testing.T) {
	mockProcesses := []OSProcessInfo{
		{
			PID:         4321,
			Name:        "node",
			CommandLine: "node /opt/mcp/github.js --token=ghp_secretToken",
		},
	}

	matcher := NewStaticProcessMatcher(mockProcesses)
	detector := NewDetector(matcher)

	configContent := `{
		"mcpServers": {
			"github-active": {
				"command": "node",
				"args": ["/opt/mcp/github.js", "--token=ghp_secretToken1234567890abcdef"]
			},
			"postgres-dormant": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"],
				"env": {
					"PASSWORD": "dbPassword123"
				}
			},
			"http-trap": {
				"serverUrl": "http://127.0.0.1:8000/mcp"
			}
		}
	}`

	servers := detector.DetectFromData("Claude Desktop", "/mock/claude_desktop_config.json", []byte(configContent), "mcpServers")

	// 1. Assert exactly 2 stdio servers emitted (HTTP trap MUST be completely dropped)
	if len(servers) != 2 {
		t.Fatalf("expected 2 stdio servers (HTTP dropped), got %d", len(servers))
	}

	serverMap := make(map[string]types.StdioDiscoveredServer)
	for _, s := range servers {
		serverMap[s.ServerName] = s
	}

	// 2. Active server upgraded to ConfidenceConfirmed via Layer 3
	active, ok := serverMap["github-active"]
	if !ok {
		t.Fatalf("missing github-active server")
	}
	if active.MCPConfidence != types.ConfidenceConfirmed {
		t.Errorf("expected ConfidenceConfirmed for active process, got %s", active.MCPConfidence)
	}
	if !active.ProcessMatchFound || active.MatchedPID != 4321 {
		t.Errorf("expected ProcessMatchFound=true with PID 4321, got matched=%v, pid=%d", active.ProcessMatchFound, active.MatchedPID)
	}
	if strings.Contains(active.ArgsSummary, "secretToken1234567890") {
		t.Errorf("active server args leaked raw secret: %s", active.ArgsSummary)
	}

	// 3. Dormant server remains ConfidenceLikely
	dormant, ok := serverMap["postgres-dormant"]
	if !ok {
		t.Fatalf("missing postgres-dormant server")
	}
	if dormant.MCPConfidence != types.ConfidenceLikely {
		t.Errorf("expected ConfidenceLikely for dormant server, got %s", dormant.MCPConfidence)
	}
	if dormant.ProcessMatchFound || dormant.MatchedPID != 0 {
		t.Errorf("expected ProcessMatchFound=false for dormant server, got matched=%v, pid=%d", dormant.ProcessMatchFound, dormant.MatchedPID)
	}
	if !dormant.HasEnvBlock {
		t.Errorf("expected HasEnvBlock=true for postgres server")
	}

	// 4. Assert HTTP trap is NOT present anywhere in output
	if _, exists := serverMap["http-trap"]; exists {
		t.Errorf("CRITICAL: http-trap was not dropped and leaked into stdio findings")
	}
}

// TestStdioDetector_NonMCPJSONTrap tests that generic JSON configs produce 0 findings.
func TestStdioDetector_NonMCPJSONTrap(t *testing.T) {
	detector := NewDetector(nil)

	nonMCPContent := `{
		"name": "my-node-app",
		"version": "1.0.0",
		"scripts": {
			"start": "node index.js"
		}
	}`

	servers := detector.DetectFromData("VS Code", "/mock/package.json", []byte(nonMCPContent), "mcpServers")
	if len(servers) != 0 {
		t.Errorf("expected 0 servers for non-MCP JSON trap, got %d", len(servers))
	}
}
