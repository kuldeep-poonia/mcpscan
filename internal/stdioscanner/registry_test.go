package stdioscanner

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistry_ToolCoverage verifies that exactly the 4 approved tools are registered for all 3 major OS platforms.
func TestRegistry_ToolCoverage(t *testing.T) {
	expectedTools := []string{"Claude Desktop", "Cursor", "Antigravity", "VS Code"}
	platforms := []string{"windows", "darwin", "linux"}

	for _, osName := range platforms {
		t.Run(osName, func(t *testing.T) {
			mockEnv := func(key string) string {
				switch key {
				case "APPDATA":
					return `C:\Users\testuser\AppData\Roaming`
				case "USERPROFILE":
					return `C:\Users\testuser`
				case "HOME":
					return `/home/testuser`
				default:
					return ""
				}
			}

			resolved := ResolveConfigPaths(osName, mockEnv)
			if len(resolved) != len(expectedTools) {
				t.Fatalf("[%s] expected %d tools resolved, got %d", osName, len(expectedTools), len(resolved))
			}

			seen := make(map[string]bool)
			for _, r := range resolved {
				seen[r.ToolName] = true
				if r.Path == "" || r.Path == "." {
					t.Errorf("[%s] tool %s resolved to invalid path: %s", osName, r.ToolName, r.Path)
				}
				if r.RootKey != "mcpServers" {
					t.Errorf("[%s] tool %s root key mismatch: %s", osName, r.ToolName, r.RootKey)
				}
			}

			for _, tool := range expectedTools {
				if !seen[tool] {
					t.Errorf("[%s] missing expected tool in registry: %s", osName, tool)
				}
			}
		})
	}
}

// TestExpandPath_WindowsEnvironment tests Windows environment variable expansion.
func TestExpandPath_WindowsEnvironment(t *testing.T) {
	mockEnv := func(key string) string {
		if key == "APPDATA" {
			return `C:\Users\tester\AppData\Roaming`
		}
		return ""
	}

	raw := `"${APPDATA}\Claude\claude_desktop_config.json"`
	expanded := ExpandPath(raw, mockEnv)

	if !strings.Contains(expanded, `AppData\Roaming\Claude\claude_desktop_config.json`) {
		t.Errorf("unexpected expanded Windows path: %s", expanded)
	}
}

// TestExpandPath_UnixEnvironment tests Unix environment variable expansion.
func TestExpandPath_UnixEnvironment(t *testing.T) {
	mockEnv := func(key string) string {
		if key == "HOME" {
			return `/home/tester`
		}
		return ""
	}

	raw := "${HOME}/.config/Claude/claude_desktop_config.json"
	expanded := ExpandPath(raw, mockEnv)

	if !strings.Contains(filepath.ToSlash(expanded), "Claude/claude_desktop_config.json") {
		t.Errorf("unexpected expanded Unix path: %s", expanded)
	}
}
