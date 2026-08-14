package stdioscanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseConfigFile_ValidStdioConfig tests parsing of standard Claude/Cursor/Antigravity config format.
func TestParseConfigFile_ValidStdioConfig(t *testing.T) {
	jsonContent := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/test/Desktop"]
			},
			"github": {
				"command": "node",
				"args": ["/opt/mcp/github.js", "--token=ghp_secretToken1234567890abcdef"],
				"env": {
					"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_realSecretTokenValueHere123456"
				}
			},
			"remote-api": {
				"serverUrl": "http://127.0.0.1:8000/sse"
			}
		}
	}`

	parsed, err := ParseConfigFile([]byte(jsonContent), "mcpServers")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(parsed) != 3 {
		t.Fatalf("expected 3 parsed servers, got %d", len(parsed))
	}

	serverMap := make(map[string]ParsedServerDef)
	for _, p := range parsed {
		serverMap[p.ServerName] = p
	}

	// 1. Filesystem server verification
	fs, ok := serverMap["filesystem"]
	if !ok || fs.Command != "npx" || fs.IsHTTP || fs.HasEnvBlock {
		t.Errorf("filesystem server parse mismatch: %+v", fs)
	}

	// 2. GitHub server verification (with args secret masking and env block presence)
	gh, ok := serverMap["github"]
	if !ok || gh.Command != "node" || gh.IsHTTP || !gh.HasEnvBlock {
		t.Errorf("github server parse mismatch: %+v", gh)
	}
	// Assert secret in args was masked
	if strings.Contains(gh.ArgsSummary, "secretToken1234567890") {
		t.Errorf("GitHub server args leaked secret in summary: %s", gh.ArgsSummary)
	}
	if !strings.Contains(gh.ArgsSummary, "--token=ghp...def") {
		t.Errorf("expected masked token in GitHub args summary, got: %s", gh.ArgsSummary)
	}

	// 3. Remote API server verification (HTTP entry flagged)
	remote, ok := serverMap["remote-api"]
	if !ok || !remote.IsHTTP {
		t.Errorf("remote-api expected IsHTTP=true, got: %+v", remote)
	}
}

// TestParseConfigFile_InvalidJSON tests graceful error on malformed JSON.
func TestParseConfigFile_InvalidJSON(t *testing.T) {
	invalidJSON := `{"mcpServers": { broken json here`
	_, err := ParseConfigFile([]byte(invalidJSON), "mcpServers")
	if err == nil {
		t.Errorf("expected error for invalid JSON, got nil")
	}
}

// TestParseConfigFile_MissingRootKey tests error when expected root key is absent.
func TestParseConfigFile_MissingRootKey(t *testing.T) {
	jsonWithoutRoot := `{"otherSettings": {"theme": "dark"}}`
	_, err := ParseConfigFile([]byte(jsonWithoutRoot), "mcpServers")
	if err == nil {
		t.Errorf("expected ErrMissingRootKey, got nil")
	}
}

// TestReadConfigFile_SizeLimit tests 5MB file read cap.
func TestReadConfigFile_SizeLimit(t *testing.T) {
	tempDir := t.TempDir()
	largeFilePath := filepath.Join(tempDir, "large_config.json")

	// Create a file slightly larger than 5MB (5MB + 10KB)
	largeData := make([]byte, MaxConfigFileSize+10*1024)
	for i := range largeData {
		largeData[i] = 'a'
	}

	if err := os.WriteFile(largeFilePath, largeData, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := ReadConfigFile(largeFilePath)
	if err == nil {
		t.Fatalf("expected ErrFileTooLarge, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Errorf("expected size limit error message, got: %v", err)
	}
}

// TestZeroRawSecretLeakage_FullPipelineAudit strictly asserts that raw API keys, passwords, and tokens
// NEVER leak into any parsed struct field or serialized JSON representation.
func TestZeroRawSecretLeakage_FullPipelineAudit(t *testing.T) {
	rawSecretKey := "sk-ant-api03-PROD_SUPER_SECRET_KEY_99999999"
	rawEnvToken := "ghp_VERY_CONFIDENTIAL_PERSONAL_ACCESS_TOKEN_8888"
	rawPassword := "DatabaseRootPasswordXYZ123456!"

	configWithSecrets := `{
		"mcpServers": {
			"secure-service": {
				"command": "python",
				"args": [
					"start.py",
					"--api-key=` + rawSecretKey + `",
					"--password=` + rawPassword + `"
				],
				"env": {
					"GITHUB_TOKEN": "` + rawEnvToken + `",
					"DATABASE_URL": "postgresql://user:` + rawPassword + `@localhost:5432/prod"
				}
			}
		}
	}`

	parsed, err := ParseConfigFile([]byte(configWithSecrets), "mcpServers")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed server, got %d", len(parsed))
	}

	srv := parsed[0]

	// 1. Assert raw secrets do not exist in any string field
	if strings.Contains(srv.Command, rawSecretKey) || strings.Contains(srv.Command, rawPassword) {
		t.Fatalf("CRITICAL SECURITY LEAK: raw secret leaked into Command field: %s", srv.Command)
	}
	if strings.Contains(srv.ArgsSummary, rawSecretKey) || strings.Contains(srv.ArgsSummary, rawPassword) || strings.Contains(srv.ArgsSummary, rawEnvToken) {
		t.Fatalf("CRITICAL SECURITY LEAK: raw secret leaked into ArgsSummary field: %s", srv.ArgsSummary)
	}

	// 2. Assert env block presence is marked true without any content
	if !srv.HasEnvBlock {
		t.Errorf("expected HasEnvBlock=true, got false")
	}

	// 3. Serialize to JSON and assert zero raw secret substrings exist in JSON payload
	jsonBytes, err := json.Marshal(srv)
	if err != nil {
		t.Fatalf("failed to marshal parsed server: %v", err)
	}
	jsonStr := string(jsonBytes)

	if strings.Contains(jsonStr, rawSecretKey) {
		t.Fatalf("CRITICAL SECURITY LEAK: JSON output contains raw secret key: %s", jsonStr)
	}
	if strings.Contains(jsonStr, rawEnvToken) {
		t.Fatalf("CRITICAL SECURITY LEAK: JSON output contains raw env token: %s", jsonStr)
	}
	if strings.Contains(jsonStr, rawPassword) {
		t.Fatalf("CRITICAL SECURITY LEAK: JSON output contains raw password: %s", jsonStr)
	}

	t.Logf("Zero Raw Secret Leakage Audit: PASS (Sanitized JSON: %s)", jsonStr)
}

