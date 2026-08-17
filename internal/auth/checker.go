// Package auth implements non-destructive, single-request authentication status checking.
package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"mcpscan/pkg/types"
)

// Maximum response body size (1MB) to defend against memory exhaustion bombs.
const maxResponseBodySize = 1024 * 1024

// Checker performs unauthenticated probe requests against detected MCP servers.
type Checker struct {
	timeout    time.Duration
	httpClient *http.Client
}

// NewChecker constructs a Checker instance with the specified timeout.
func NewChecker(timeout time.Duration) *Checker {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Checker{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				ResponseHeaderTimeout: timeout,
				IdleConnTimeout:       timeout,
				DisableKeepAlives:     true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

// CheckAuth performs exactly ONE unauthenticated probe request to determine authentication status.
// Hard constraint: Must NEVER retry, brute-force, or send multiple requests.
func (c *Checker) CheckAuth(ctx context.Context, server types.DiscoveredServer) (types.DiscoveredServer, error) {
	// Default initial state
	server.AuthStatus = types.AuthUnknown
	server.AuthConfidence = types.AuthConfidenceLow
	server.RiskLevel = types.RiskMedium

	// If server required auth on initialize handshake itself -> unverifiable_protected
	if server.MCPConfidence == types.ConfidenceUnverifiableProtected {
		server.AuthStatus = types.AuthProtected
		server.AuthConfidence = types.AuthConfidenceMedium
		server.RiskLevel = types.RiskMedium
		return server, nil
	}

	// If service is not an MCP server (ConfidenceNone), skip probe
	if server.MCPConfidence == types.ConfidenceNone {
		server.RiskLevel = types.RiskLow
		return server, nil
	}

	scheme := "http"
	if server.TransportSecurity == types.TransportSecurityHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, server.IP, server.Port)

	// Single probe payload: low-privilege informational request (`tools/list`)
	probeReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "tools/list",
	}

	reqData, err := json.Marshal(probeReq)
	if err != nil {
		return server, nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(reqData))
	if err != nil {
		return server, nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpscan/1.0.0")

	// Execute EXACTLY ONE unauthenticated HTTP request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network error / timeout -> AuthUnknown (Low confidence)
		return server, nil
	}
	defer resp.Body.Close()

	// Evaluate HTTP Response Status Code
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		// 401/403 -> PROTECTED (High confidence)
		server.AuthStatus = types.AuthProtected
		server.AuthConfidence = types.AuthConfidenceHigh
		server.RiskLevel = types.RiskLow
		return server, nil

	case http.StatusOK:
		// Read body with limit
		limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
		bodyBytes, readErr := io.ReadAll(limitedReader)
		if readErr != nil {
			return server, nil
		}

		// Verify response is valid JSON-RPC
		var rpcResp struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      interface{}     `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}

		if json.Unmarshal(bodyBytes, &rpcResp) == nil && rpcResp.JSONRPC == "2.0" {
			// 200 OK + valid JSON-RPC -> UNPROTECTED (High confidence)
			server.AuthStatus = types.AuthUnprotected
			server.AuthConfidence = types.AuthConfidenceHigh
			server.RiskLevel = types.RiskHigh
			return server, nil
		}

		// 200 OK but malformed body -> AuthUnknown
		return server, nil

	default:
		// Any other status code (e.g. 500, 404) -> AuthUnknown
		return server, nil
	}
}

// CheckAuthBatch executes auth checking concurrently over a list of discovered servers while maintaining single-request discipline.
func (c *Checker) CheckAuthBatch(ctx context.Context, servers []types.DiscoveredServer) ([]types.DiscoveredServer, error) {
	if len(servers) == 0 {
		return []types.DiscoveredServer{}, nil
	}

	results := make([]types.DiscoveredServer, len(servers))
	var wg sync.WaitGroup

	for i, srv := range servers {
		wg.Add(1)
		go func(idx int, target types.DiscoveredServer) {
			defer wg.Done()
			res, _ := c.CheckAuth(ctx, target)
			results[idx] = res
		}(i, srv)
	}

	wg.Wait()
	return results, nil
}
