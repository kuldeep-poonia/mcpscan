// Package stdioscanner implements opt-in local stdio-transport MCP server discovery.
package stdioscanner

import (
	"os"
	"path/filepath"
	"strings"
)

// ToolConfigPath defines a known AI tool and its OS-specific configuration path template.
type ToolConfigPath struct {
	ToolName       string // Name of the AI tool (e.g., "Claude Desktop", "Antigravity", "Cursor", "VS Code")
	OS             string // Target OS: "windows", "darwin", "linux", or "all"
	RawPathPattern string // OS-specific path template supporting environment variables
	RootKey        string // Expected JSON root key containing server definitions (e.g., "mcpServers")
}

// ResolvedToolPath represents a fully resolved configuration path for an AI tool.
type ResolvedToolPath struct {
	ToolName string
	Path     string
	RootKey  string
}

// DefaultRegistry contains the static, versioned list of known AI tool configuration paths.
// Strictly locked to the 4 approved tools: Claude Desktop, Antigravity, Cursor, and VS Code.
var DefaultRegistry = []ToolConfigPath{
	// Claude Desktop
	{
		ToolName:       "Claude Desktop",
		OS:             "windows",
		RawPathPattern: `"${APPDATA}\Claude\claude_desktop_config.json"`,
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Claude Desktop",
		OS:             "darwin",
		RawPathPattern: "${HOME}/Library/Application Support/Claude/claude_desktop_config.json",
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Claude Desktop",
		OS:             "linux",
		RawPathPattern: "${HOME}/.config/Claude/claude_desktop_config.json",
		RootKey:        "mcpServers",
	},

	// Cursor
	{
		ToolName:       "Cursor",
		OS:             "windows",
		RawPathPattern: `"${USERPROFILE}\.cursor\mcp.json"`,
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Cursor",
		OS:             "darwin",
		RawPathPattern: "${HOME}/.cursor/mcp.json",
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Cursor",
		OS:             "linux",
		RawPathPattern: "${HOME}/.cursor/mcp.json",
		RootKey:        "mcpServers",
	},

	// Antigravity (Gemini IDE)
	{
		ToolName:       "Antigravity",
		OS:             "windows",
		RawPathPattern: `"${USERPROFILE}\.gemini\antigravity-ide\mcp_config.json"`,
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Antigravity",
		OS:             "darwin",
		RawPathPattern: "${HOME}/.gemini/antigravity-ide/mcp_config.json",
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "Antigravity",
		OS:             "linux",
		RawPathPattern: "${HOME}/.gemini/antigravity-ide/mcp_config.json",
		RootKey:        "mcpServers",
	},

	// VS Code
	{
		ToolName:       "VS Code",
		OS:             "windows",
		RawPathPattern: `"${APPDATA}\Code\User\mcp.json"`,
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "VS Code",
		OS:             "darwin",
		RawPathPattern: "${HOME}/Library/Application Support/Code/User/mcp.json",
		RootKey:        "mcpServers",
	},
	{
		ToolName:       "VS Code",
		OS:             "linux",
		RawPathPattern: "${HOME}/.config/Code/User/mcp.json",
		RootKey:        "mcpServers",
	},
}

// ExpandPath expands environment variables in a path pattern using the provided env lookup function.
func ExpandPath(rawPattern string, envGetter func(string) string) string {
	cleaned := strings.Trim(rawPattern, `"'`)
	expanded := os.Expand(cleaned, envGetter)
	return filepath.Clean(expanded)
}

// ResolveConfigPaths returns the list of resolved configuration paths for the specified OS.
func ResolveConfigPaths(targetOS string, envGetter func(string) string) []ResolvedToolPath {
	if envGetter == nil {
		envGetter = os.Getenv
	}

	var results []ResolvedToolPath
	for _, entry := range DefaultRegistry {
		if entry.OS != targetOS && entry.OS != "all" {
			continue
		}

		resolved := ExpandPath(entry.RawPathPattern, envGetter)
		if resolved == "." || resolved == "" {
			continue
		}

		results = append(results, ResolvedToolPath{
			ToolName: entry.ToolName,
			Path:     resolved,
			RootKey:  entry.RootKey,
		})
	}

	return results
}
