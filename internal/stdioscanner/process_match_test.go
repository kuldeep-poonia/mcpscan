package stdioscanner

import (
	"testing"
)

// TestProcessMatcher_ExactAndGenericMatches verifies strict process matching rules.
func TestProcessMatcher_ExactAndGenericMatches(t *testing.T) {
	mockProcesses := []OSProcessInfo{
		{
			PID:         1234,
			Name:        "node.exe",
			CommandLine: `C:\Program Files\nodejs\node.exe C:\Users\user\mcp-servers\github\dist\index.js --port 8080`,
		},
		{
			PID:         5678,
			Name:        "python.exe",
			CommandLine: `C:\Python310\python.exe -m uvicorn unrelated_app:app`,
		},
		{
			PID:         9999,
			Name:        "custom-mcp-server.exe",
			CommandLine: `C:\bin\custom-mcp-server.exe --verbose`,
		},
	}

	matcher := NewStaticProcessMatcher(mockProcesses)

	// 1. Positive generic runner match with aligned arguments
	matched, pid := matcher.FindMatch("node", "C:/Users/user/mcp-servers/github/dist/index.js")
	if !matched || pid != 1234 {
		t.Errorf("expected positive match for node with index.js, got matched=%v, pid=%d", matched, pid)
	}

	// 2. Generic runner trap: same generic binary (python), but args do NOT align -> must NOT match
	matched, pid = matcher.FindMatch("python", "server_database_mcp.py")
	if matched {
		t.Errorf("false positive: generic runner matched unrelated process (pid=%d)", pid)
	}

	// 3. Positive custom binary match
	matched, pid = matcher.FindMatch("custom-mcp-server", "--verbose")
	if !matched || pid != 9999 {
		t.Errorf("expected match for custom-mcp-server, got matched=%v, pid=%d", matched, pid)
	}

	// 4. Dormant server: no running process exists
	matched, _ = matcher.FindMatch("npx", "@modelcontextprotocol/server-postgres")
	if matched {
		t.Errorf("expected dormant server not to match any running process")
	}
}
