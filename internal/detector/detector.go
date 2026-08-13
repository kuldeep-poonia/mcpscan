// Package detector implements the 3-layer verification strategy to identify genuine HTTP MCP servers.
package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"mcpscan/pkg/types"
)

// Maximum response body size (1MB) to defend against memory exhaustion bombs.
const maxResponseBodySize = 1024 * 1024

// JSONRPCRequest represents a standard JSON-RPC 2.0 request payload.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 response payload.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// MCPInitializeResult represents the result payload of an MCP `initialize` request.
type MCPInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// Detector performs multi-layer MCP verification on open ports.
type Detector struct {
	timeout    time.Duration
	httpClient *http.Client
}

// NewDetector creates a new Detector instance with a dedicated, timeout-bound HTTP client.
func NewDetector(timeout time.Duration) *Detector {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Detector{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				ResponseHeaderTimeout: timeout,
				IdleConnTimeout:       timeout,
				DisableKeepAlives:     true,
			},
		},
	}
}

// DetectPort evaluates a single open port using the 3-layer verification strategy.
func (d *Detector) DetectPort(ctx context.Context, target types.OpenPort) (types.DiscoveredServer, error) {
	srv := types.DiscoveredServer{
		IP:              target.IP,
		Port:            target.Port,
		MCPConfidence:   types.ConfidenceNone,
		ProtocolVersion: "",
		AuthStatus:      types.AuthUnknown,
		AuthConfidence:  types.AuthConfidenceLow,
		RiskLevel:       types.RiskLow,
		DetectedAt:      time.Now().UTC(),
	}

	url := fmt.Sprintf("http://%s:%d/", target.IP, target.Port)

	// Layer 1 & 2 Probe: Send `initialize` request
	initReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "mcpscan",
				"version": "1.0.0",
			},
		},
	}

	respBody, err := d.sendJSONRPC(ctx, url, initReq)
	if err != nil {
		// Target failed HTTP handshake or timed out -> ConfidenceNone
		return srv, nil
	}

	// Layer 1 Verification: Valid JSON-RPC 2.0 response with valid ID
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return srv, nil
	}

	if rpcResp.JSONRPC != "2.0" || rpcResp.ID == nil {
		return srv, nil
	}

	// Layer 2 Verification: Check for MCP-specific required fields in result
	if len(rpcResp.Result) == 0 {
		return srv, nil
	}

	var initResult MCPInitializeResult
	if err := json.Unmarshal(rpcResp.Result, &initResult); err != nil {
		return srv, nil
	}

	// Check presence of protocolVersion or capabilities
	hasProto := strings.TrimSpace(initResult.ProtocolVersion) != ""
	hasCaps := initResult.Capabilities != nil

	if !hasProto && !hasCaps {
		// Failed Layer 2 -> Non-MCP JSON-RPC server (ConfidenceNone)
		return srv, nil
	}

	// Passed Layer 1 + Layer 2 -> Likely MCP Server
	srv.MCPConfidence = types.ConfidenceLikely
	srv.ProtocolVersion = initResult.ProtocolVersion
	if srv.ProtocolVersion == "" {
		srv.ProtocolVersion = "2024-11-05"
	}

	// Layer 3 Probe: Send secondary method (`tools/list`) to cross-confirm protocol consistency
	toolsReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	toolsBody, err := d.sendJSONRPC(ctx, url, toolsReq)
	if err == nil {
		var toolsResp JSONRPCResponse
		if json.Unmarshal(toolsBody, &toolsResp) == nil {
			if toolsResp.JSONRPC == "2.0" && (len(toolsResp.Result) > 0 || toolsResp.Error != nil) {
				// Layer 3 passed -> Confirmed MCP Server
				srv.MCPConfidence = types.ConfidenceConfirmed
			}
		}
	}

	return srv, nil
}

// DetectBatch evaluates a list of open ports concurrently.
func (d *Detector) DetectBatch(ctx context.Context, openPorts []types.OpenPort) ([]types.DiscoveredServer, error) {
	if len(openPorts) == 0 {
		return []types.DiscoveredServer{}, nil
	}

	results := make([]types.DiscoveredServer, len(openPorts))
	var wg sync.WaitGroup

	for i, port := range openPorts {
		wg.Add(1)
		go func(idx int, target types.OpenPort) {
			defer wg.Done()
			srv, _ := d.DetectPort(ctx, target)
			results[idx] = srv
		}(i, port)
	}

	wg.Wait()
	return results, nil
}

// sendJSONRPC constructs and sends an HTTP POST JSON-RPC request with strict timeouts.
func (d *Detector) sendJSONRPC(ctx context.Context, url string, payload JSONRPCRequest) ([]byte, error) {
	reqData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpscan/1.0.0")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read body even on error status to check for JSON-RPC error payload
	}

	// Limit reader size to defend against response bombs
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
