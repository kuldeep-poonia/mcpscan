package stdioscanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// MaxConfigFileSize defines the maximum permissible config file read size (5MB).
const MaxConfigFileSize = 5 * 1024 * 1024

// Common errors returned by the config file reader and parser.
var (
	ErrFileTooLarge     = errors.New("config file exceeds maximum allowed size of 5MB")
	ErrInvalidJSON      = errors.New("file content is not valid JSON")
	ErrMissingRootKey   = errors.New("expected root key not found in config JSON")
	ErrEmptyConfig      = errors.New("config file contains no server definitions")
)

// RawConfigFile represents the expected top-level JSON structure of an AI tool MCP config.
type RawConfigFile struct {
	MCPServers map[string]RawServerDef `json:"mcpServers"`
}

// RawServerDef represents a single MCP server definition entry in the config file.
type RawServerDef struct {
	Command   *string                `json:"command,omitempty"`
	Args      []string               `json:"args,omitempty"`
	Env       map[string]interface{} `json:"env,omitempty"`
	ServerURL *string                `json:"serverUrl,omitempty"`
}

// ParsedServerDef represents a sanitized, extracted MCP server definition.
type ParsedServerDef struct {
	ServerName  string
	Command     string
	ArgsSummary string
	HasEnvBlock bool
	IsHTTP      bool // true if serverUrl was defined instead of command
}

// ReadConfigFile safely reads a config file from disk enforcing the 5MB size limit.
func ReadConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Enforce 5MB limit plus 1 byte to detect overflow
	limitedReader := io.LimitReader(file, MaxConfigFileSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", path, err)
	}

	if len(data) > MaxConfigFileSize {
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrFileTooLarge, path, len(data))
	}

	return data, nil
}

// ParseConfigFile parses raw JSON bytes into sanitized ParsedServerDef records.
// Guarantees:
// 1. Command and Args strings are masked immediately during parsing.
// 2. Env block contents are NEVER stored or recorded — only HasEnvBlock boolean flag is set.
// 3. serverUrl entries are flagged as IsHTTP to be excluded from stdio detection.
func ParseConfigFile(data []byte, rootKey string) ([]ParsedServerDef, error) {
	if len(data) == 0 {
		return nil, ErrEmptyConfig
	}

	if rootKey == "" {
		rootKey = "mcpServers"
	}

	// Parse as generic map first to extract the dynamic rootKey
	var genericMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &genericMap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	rootRaw, ok := genericMap[rootKey]
	if !ok || len(rootRaw) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrMissingRootKey, rootKey)
	}

	var serversMap map[string]RawServerDef
	if err := json.Unmarshal(rootRaw, &serversMap); err != nil {
		return nil, fmt.Errorf("%w: %q is not a valid server map: %v", ErrInvalidJSON, rootKey, err)
	}

	if len(serversMap) == 0 {
		return nil, ErrEmptyConfig
	}

	var results []ParsedServerDef
	for name, def := range serversMap {
		parsed := ParsedServerDef{
			ServerName: name,
		}

		// Check if it's an HTTP transport entry (serverUrl present)
		if def.ServerURL != nil && *def.ServerURL != "" {
			parsed.IsHTTP = true
			results = append(results, parsed)
			continue
		}

		// Stdio transport: extract command and args with immediate secret masking
		if def.Command != nil {
			parsed.Command = MaskString(*def.Command)
		}
		if len(def.Args) > 0 {
			parsed.ArgsSummary = SummarizeArgs(def.Args)
		}

		// Record presence of env block without storing any keys or values
		if len(def.Env) > 0 {
			parsed.HasEnvBlock = true
		}

		results = append(results, parsed)
	}

	return results, nil
}
