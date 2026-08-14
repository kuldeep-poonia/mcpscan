package stdioscanner

import (
	"context"
	"os"
	"time"

	"mcpscan/pkg/types"
)

// StdioDetector discovers and validates stdio MCP server configurations across known AI tools.
type StdioDetector struct {
	processMatcher ProcessMatcher
}

// NewDetector initializes a new StdioDetector with the provided ProcessMatcher.
func NewDetector(processMatcher ProcessMatcher) *StdioDetector {
	if processMatcher == nil {
		processMatcher = NewOSProcessMatcher()
	}
	return &StdioDetector{
		processMatcher: processMatcher,
	}
}

// DetectLocal scans all registered AI tool configuration files on the local machine.
func (d *StdioDetector) DetectLocal(ctx context.Context, targetOS string, envGetter func(string) string) ([]types.StdioDiscoveredServer, error) {
	resolvedPaths := ResolveConfigPaths(targetOS, envGetter)
	var allDiscovered []types.StdioDiscoveredServer

	for _, tool := range resolvedPaths {
		select {
		case <-ctx.Done():
			return allDiscovered, ctx.Err()
		default:
		}

		// Check if file exists on disk (silently skip if tool not installed)
		if _, err := os.Stat(tool.Path); os.IsNotExist(err) {
			continue
		}

		// Safely read config file enforcing 5MB limit
		data, err := ReadConfigFile(tool.Path)
		if err != nil {
			continue // Skip unreadable or oversized files gracefully
		}

		// Run detection layers 1, 2, and 3
		discovered := d.DetectFromData(tool.ToolName, tool.Path, data, tool.RootKey)
		allDiscovered = append(allDiscovered, discovered...)
	}

	return allDiscovered, nil
}

// DetectFromData processes raw configuration bytes through detection Layer 1, Layer 2, and Layer 3.
func (d *StdioDetector) DetectFromData(toolName, path string, data []byte, rootKey string) []types.StdioDiscoveredServer {
	// Layer 1 & 2: Parse and validate schema structure
	parsedDefs, err := ParseConfigFile(data, rootKey)
	if err != nil {
		return nil // Layer 1/2 failed: skip silently
	}

	var servers []types.StdioDiscoveredServer
	now := time.Now().UTC()

	for _, def := range parsedDefs {
		// Hard Rule: Drop HTTP transport entries completely (has serverUrl) to avoid double-counting
		if def.IsHTTP || def.Command == "" {
			continue
		}

		// Layer 2 passed: structurally valid stdio server definition found (ConfidenceLikely)
		server := types.StdioDiscoveredServer{
			SourceTool:    toolName,
			ConfigFile:    path,
			ServerName:    def.ServerName,
			Command:       def.Command,
			ArgsSummary:   def.ArgsSummary,
			HasEnvBlock:   def.HasEnvBlock,
			MCPConfidence: types.ConfidenceLikely,
			DetectedAt:    now,
		}

		// Layer 3: Process cross-referencing
		if d.processMatcher != nil {
			matched, pid := d.processMatcher.FindMatch(def.Command, def.ArgsSummary)
			if matched {
				server.MCPConfidence = types.ConfidenceConfirmed
				server.ProcessMatchFound = true
				server.MatchedPID = pid
			}
		}

		servers = append(servers, server)
	}

	return servers
}
