// Package detector implements the 3-layer verification strategy to identify genuine HTTP MCP servers and parameter safety heuristics.
package detector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"mcpscan/pkg/types"
)

// Maximum response body size (1MB) to defend against memory exhaustion bombs.
const maxResponseBodySize = 1024 * 1024

// HighRiskExactTerms contains exact parameter names that represent direct system access.
var HighRiskExactTerms = map[string]bool{
	"command":       true,
	"cmd":           true,
	"path":          true,
	"filepath":      true,
	"file_path":     true,
	"dirpath":       true,
	"dir_path":      true,
	"query":         true,
	"sql":           true,
	"sql_query":     true,
	"raw_query":     true,
	"script":        true,
	"code":          true,
	"exec":          true,
	"eval":          true,
	"shell":         true,
	"shell_command": true,
	"bash_command":  true,
	"exec_command":  true,
	"stdin":         true,
}

// SafeParameterDenyList contains parameter names that contain high-risk tokens but represent benign non-system values.
var SafeParameterDenyList = map[string]bool{
	"zip_code":      true,
	"zipcode":       true,
	"postal_code":   true,
	"postalcode":    true,
	"area_code":     true,
	"areacode":      true,
	"country_code":  true,
	"countrycode":   true,
	"currency_code": true,
	"currencycode":  true,
	"language_code": true,
	"languagecode":  true,
	"status_code":   true,
	"statuscode":    true,
	"error_code":    true,
	"errorcode":     true,
	"response_code": true,
	"responsecode":  true,
	"http_code":     true,
	"dial_code":     true,
	"dialcode":      true,
	"color_code":    true,
	"colorcode":     true,
	"barcode":       true,
	"bar_code":      true,
	"qrcode":        true,
	"qr_code":       true,
	"promo_code":    true,
	"promocode":     true,
	"discount_code": true,
	"coupon_code":   true,
	"passcode":      true,
	"access_code":   true,
	"pin_code":      true,
}

// isDangerousParameterName checks if paramName represents a high-risk system parameter using exact and tokenized matching.
func isDangerousParameterName(name string) bool {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" {
		return false
	}

	// 1. Check safe deny-list
	if SafeParameterDenyList[norm] {
		return false
	}

	// 2. Check exact match
	if HighRiskExactTerms[norm] {
		return true
	}

	// 3. Tokenize delimiters (_, -, .)
	var tokens []string
	var current strings.Builder
	for _, r := range norm {
		if r == '_' || r == '-' || r == '.' || r == ' ' {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	for i, t := range tokens {
		if HighRiskExactTerms[t] {
			if t == "code" && i > 0 {
				prev := tokens[i-1]
				if prev == "zip" || prev == "postal" || prev == "area" || prev == "country" || prev == "currency" ||
					prev == "language" || prev == "status" || prev == "error" || prev == "response" || prev == "http" ||
					prev == "color" || prev == "bar" || prev == "qr" || prev == "promo" || prev == "discount" || prev == "coupon" {
					continue
				}
			}
			return true
		}
	}

	return false
}

// isUnconstrainedString checks if a JSON Schema property accepts unconstrained string/any values.
func isUnconstrainedString(prop map[string]interface{}) (bool, string) {
	if prop == nil {
		return true, "any"
	}

	// 1. If enum is present and non-empty -> constrained -> safe
	if enumRaw, hasEnum := prop["enum"]; hasEnum && enumRaw != nil {
		if enumList, ok := enumRaw.([]interface{}); ok && len(enumList) > 0 {
			return false, ""
		}
	}

	// 2. Inspect type field
	typeRaw, hasType := prop["type"]
	if !hasType || typeRaw == nil {
		// Missing type -> unconstrained any type accepted
		return true, "any"
	}

	switch v := typeRaw.(type) {
	case string:
		typ := strings.ToLower(strings.TrimSpace(v))
		if typ == "string" {
			return true, "string"
		}
		return false, ""
	case []interface{}:
		var typesFound []string
		hasString := false
		for _, item := range v {
			if s, ok := item.(string); ok {
				s = strings.ToLower(strings.TrimSpace(s))
				typesFound = append(typesFound, s)
				if s == "string" {
					hasString = true
				}
			}
		}
		if hasString {
			return true, strings.Join(typesFound, "|")
		}
		return false, ""
	default:
		return false, ""
	}
}

// MCPToolsListResult represents the JSON result payload of a `tools/list` response.
type MCPToolsListResult struct {
	Tools []struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		InputSchema map[string]interface{} `json:"inputSchema"`
	} `json:"tools"`
}

// extractDangerousParameters parses tools/list response to identify unconstrained dangerous parameter shapes.
func extractDangerousParameters(respBody []byte) []types.DangerousParameter {
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil || len(rpcResp.Result) == 0 {
		return nil
	}

	var listResult MCPToolsListResult
	if err := json.Unmarshal(rpcResp.Result, &listResult); err != nil || len(listResult.Tools) == 0 {
		return nil
	}

	var dangerous []types.DangerousParameter
	for _, tool := range listResult.Tools {
		toolName := tool.Name
		if toolName == "" {
			toolName = "unnamed_tool"
		}

		if tool.InputSchema == nil {
			continue
		}

		propsRaw, ok := tool.InputSchema["properties"]
		if !ok || propsRaw == nil {
			continue
		}

		propsMap, ok := propsRaw.(map[string]interface{})
		if !ok {
			continue
		}

		for paramName, propRaw := range propsMap {
			if !isDangerousParameterName(paramName) {
				continue
			}

			propMap, _ := propRaw.(map[string]interface{})
			isDangerous, paramType := isUnconstrainedString(propMap)
			if isDangerous {
				dangerous = append(dangerous, types.DangerousParameter{
					ToolName:  toolName,
					ParamName: paramName,
					ParamType: paramType,
				})
			}
		}
	}

	return dangerous
}

// computeToolDefinitionHash calculates a deterministic SHA-256 digest over normalized tool definitions.
func computeToolDefinitionHash(respBody []byte) string {
	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil || len(rpcResp.Result) == 0 {
		return ""
	}

	var listResult MCPToolsListResult
	if err := json.Unmarshal(rpcResp.Result, &listResult); err != nil || len(listResult.Tools) == 0 {
		return ""
	}

	// Sort tools by Name ascending to eliminate arbitrary server-side ordering differences
	tools := make([]struct {
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		InputSchema map[string]interface{} `json:"inputSchema"`
	}, len(listResult.Tools))
	copy(tools, listResult.Tools)

	sort.Slice(tools, func(i, j int) bool {
		return tools[i].Name < tools[j].Name
	})

	canonicalBytes, err := json.Marshal(tools)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(hash[:])
}

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
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

// HandshakeAuthError is returned when an initialize request receives HTTP 401 or 403.
type HandshakeAuthError struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (e *HandshakeAuthError) Error() string {
	return fmt.Sprintf("handshake auth required: HTTP %d", e.StatusCode)
}

func (d *Detector) probeScheme(ctx context.Context, scheme, ip string, port int) ([]byte, *HandshakeAuthError, error) {
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
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
		if authErr, ok := err.(*HandshakeAuthError); ok {
			return nil, authErr, nil
		}
		return nil, nil, err
	}
	return respBody, nil, nil
}

// DetectPort evaluates a single open port using the 3-layer verification strategy.
func (d *Detector) DetectPort(ctx context.Context, target types.OpenPort) (types.DiscoveredServer, error) {
	srv := types.DiscoveredServer{
		IP:                target.IP,
		Port:              target.Port,
		Transport:         types.TransportHTTP,
		TransportSecurity: types.TransportSecurityNotEvaluated,
		MCPConfidence:     types.ConfidenceNone,
		ProtocolVersion:   "",
		AuthStatus:        types.AuthUnknown,
		AuthConfidence:    types.AuthConfidenceLow,
		RiskLevel:         types.RiskLow,
		DetectedAt:        time.Now().UTC(),
	}

	schemes := []struct {
		scheme   string
		security types.TransportSecurity
	}{
		{"http", types.TransportSecurityPlaintext},
		{"https", types.TransportSecurityHTTPS},
	}

	for _, s := range schemes {
		respBody, authErr, err := d.probeScheme(ctx, s.scheme, target.IP, target.Port)
		if authErr != nil {
			hasWWWAuth := authErr.Header.Get("WWW-Authenticate") != ""
			cType := strings.ToLower(authErr.Header.Get("Content-Type"))
			isJSONType := strings.Contains(cType, "application/json")

			trimmedBody := strings.TrimSpace(string(authErr.Body))
			isJSONBody := (strings.HasPrefix(trimmedBody, "{") || strings.HasPrefix(trimmedBody, "[")) && json.Valid(authErr.Body)
			isHTMLBody := strings.HasPrefix(strings.ToLower(trimmedBody), "<html") || strings.HasPrefix(strings.ToLower(trimmedBody), "<!doctype html")

			// Positive signal: WWW-Authenticate header present OR response body is JSON-shaped
			if (hasWWWAuth || isJSONType || isJSONBody) && !isHTMLBody {
				srv.MCPConfidence = types.ConfidenceUnverifiableProtected
				srv.TransportSecurity = s.security
				return srv, nil
			}
			continue
		}

		if err != nil {
			continue
		}

		// Layer 1 Verification: Valid JSON-RPC 2.0 response with valid ID
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal(respBody, &rpcResp); err != nil {
			continue
		}

		if rpcResp.JSONRPC != "2.0" || rpcResp.ID == nil {
			continue
		}

		// Layer 2 Verification: Check for MCP-specific required fields in result
		if len(rpcResp.Result) == 0 {
			continue
		}

		var initResult MCPInitializeResult
		if err := json.Unmarshal(rpcResp.Result, &initResult); err != nil {
			continue
		}

		// Check presence of protocolVersion or capabilities
		hasProto := strings.TrimSpace(initResult.ProtocolVersion) != ""
		hasCaps := initResult.Capabilities != nil

		if !hasProto && !hasCaps {
			continue
		}

		// Passed Layer 1 + Layer 2 -> Likely MCP Server
		srv.MCPConfidence = types.ConfidenceLikely
		srv.TransportSecurity = s.security
		srv.ProtocolVersion = initResult.ProtocolVersion
		srv.ServerName = initResult.ServerInfo.Name
		if srv.ProtocolVersion == "" {
			srv.ProtocolVersion = "2024-11-05"
		}

		// Layer 3 Probe: Send secondary method (`tools/list`) to cross-confirm protocol consistency
		toolsReq := JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      2,
			Method:  "tools/list",
		}
		toolsURL := fmt.Sprintf("%s://%s:%d/", s.scheme, target.IP, target.Port)
		toolsRespBody, toolsErr := d.sendJSONRPC(ctx, toolsURL, toolsReq)
		if toolsErr == nil {
			var toolsRPCResp JSONRPCResponse
			if err := json.Unmarshal(toolsRespBody, &toolsRPCResp); err == nil {
				if toolsRPCResp.JSONRPC == "2.0" && (toolsRPCResp.Result != nil || toolsRPCResp.Error != nil) {
					srv.MCPConfidence = types.ConfidenceConfirmed
					if len(toolsRPCResp.Result) > 0 {
						srv.DangerousParams = extractDangerousParameters(toolsRespBody)
						srv.ToolDefinitionHash = computeToolDefinitionHash(toolsRespBody)
					}
				}
			}
		}

		return srv, nil
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
		bodyBytes, _ := io.ReadAll(limitedReader)
		return nil, &HandshakeAuthError{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			Body:       bodyBytes,
		}
	}

	// Limit reader size to defend against response bombs
	limitedReader := io.LimitReader(resp.Body, maxResponseBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
