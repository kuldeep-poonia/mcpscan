package detector

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

// TestTruePositiveRate verifies detection accuracy across 4 distinct valid MCP server fixtures (>= 95% threshold).
func TestTruePositiveRate(t *testing.T) {
	// 4 distinct valid MCP server fixtures
	fixtures := []http.HandlerFunc{
		// 1. Full MCP Server: full capabilities, protocolVersion 2024-11-05, full serverInfo
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			bodyStr := string(buf[:n])
			if strings.Contains(bodyStr, "tools/list") {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"test_tool"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"full-mcp","version":"1.2.0"}}}`))
		},
		// 2. Minimal MCP Server: minimal capabilities, no serverInfo
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			bodyStr := string(buf[:n])
			if strings.Contains(bodyStr, "tools/list") {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}}`))
		},
		// 3. Legacy/Custom MCP Server: protocolVersion 2024-10-07, custom capability map
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			bodyStr := string(buf[:n])
			if strings.Contains(bodyStr, "tools/list") {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"legacy_tool"}]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-10-07","capabilities":{"experimental":{}}}}`))
		},
		// 4. Dynamic MCP Server: protocolVersion v1.0, capabilities empty map, handles tools/list cleanly
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			bodyStr := string(buf[:n])
			if strings.Contains(bodyStr, "tools/list") {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"v1.0","capabilities":{}}}`))
		},
	}

	d := NewDetector(1 * time.Second)
	truePositives := 0

	for i, handler := range fixtures {
		ts := httptest.NewServer(handler)
		host, portStr, _ := netSplitHostPort(ts.URL)
		port, _ := strconv.Atoi(portStr)

		srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
		ts.Close()

		if err != nil {
			t.Errorf("fixture %d error: %v", i+1, err)
			continue
		}

		if srv.MCPConfidence == types.ConfidenceConfirmed || srv.MCPConfidence == types.ConfidenceLikely {
			truePositives++
		} else {
			t.Errorf("fixture %d failed detection, got confidence: %v", i+1, srv.MCPConfidence)
		}
	}

	tpr := (float64(truePositives) / float64(len(fixtures))) * 100.0
	t.Logf("True Positive Rate across %d distinct MCP fixtures: %.2f%%", len(fixtures), tpr)

	if tpr < 95.0 {
		t.Errorf("true positive rate %.2f%% below 95.0%% threshold", tpr)
	}
}

// TestFalsePositiveRate verifies false positive rate across 4 distinct non-MCP JSON-RPC traps (<= 1% threshold).
func TestFalsePositiveRate(t *testing.T) {
	// 4 distinct non-MCP JSON-RPC trap fixtures
	traps := []http.HandlerFunc{
		// 1. Ethereum JSON-RPC node trap
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"eth_blockNumber":"0x123456","network":"mainnet"}}`))
		},
		// 2. Bitcoin JSON-RPC node trap
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"chain":"main","blocks":700000,"verificationprogress":0.999}}`))
		},
		// 3. Generic Math / Echo JSON-RPC service trap
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":42}`))
		},
		// 4. JSON-RPC Method Not Found Error trap
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method initialize not found"}}`))
		},
	}

	d := NewDetector(1 * time.Second)
	falsePositives := 0

	for i, handler := range traps {
		ts := httptest.NewServer(handler)
		host, portStr, _ := netSplitHostPort(ts.URL)
		port, _ := strconv.Atoi(portStr)

		srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
		ts.Close()

		if err != nil {
			t.Errorf("trap %d error: %v", i+1, err)
			continue
		}

		if srv.MCPConfidence != types.ConfidenceNone {
			falsePositives++
			t.Errorf("trap %d incorrectly detected as MCP with confidence: %v", i+1, srv.MCPConfidence)
		}
	}

	fpr := (float64(falsePositives) / float64(len(traps))) * 100.0
	t.Logf("False Positive Rate across %d distinct non-MCP traps: %.2f%%", len(traps), fpr)

	if fpr > 1.0 {
		t.Errorf("false positive rate %.2f%% exceeds 1.0%% threshold", fpr)
	}
}

// TestConfidenceNoneClassification asserts explicit positive classification of ConfidenceNone for non-MCP targets.
func TestConfidenceNoneClassification(t *testing.T) {
	// 1. Plain HTML server fixture
	htmlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Welcome to Apache Web Server</body></html>"))
	}))
	defer htmlServer.Close()

	hostHTML, portHTMLStr, _ := netSplitHostPort(htmlServer.URL)
	portHTML, _ := strconv.Atoi(portHTMLStr)

	d := NewDetector(500 * time.Millisecond)
	srvHTML, err := d.DetectPort(context.Background(), types.OpenPort{IP: hostHTML, Port: portHTML})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srvHTML.MCPConfidence != types.ConfidenceNone {
		t.Errorf("expected ConfidenceNone for plain HTML server, got %v", srvHTML.MCPConfidence)
	}
}

// TestMalformedResponseResilience executes 1,000 distinct malformed/hostile payloads with 0 panics or crashes.
func TestMalformedResponseResilience(t *testing.T) {
	var currentPayload string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(currentPayload))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(100 * time.Millisecond)

	// Fuzz generator for 1,000 distinct payloads
	payloadTemplates := []string{
		`{"jsonrpc":"2.0"}`,
		`{"jsonrpc":"1.0","id":1}`,
		`{"jsonrpc":"2.0","id":null,"result":{}}`,
		`{"jsonrpc":"2.0","id":1,"result":null}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`,
		`<html><body>Server Error 500</body></html>`,
		`{"result": {"protocolVersion": "2024-11-05"}}`, // missing jsonrpc 2.0
		`\x00\x01\x02\x03\x04\x05`,
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":12345}}`,
		`{"jsonrpc":"2.0","id":1,"result":{"capabilities":"not_a_map"}}`,
		`[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]`,
		`{"a":` + strings.Repeat(`{"b":`, 50) + `1` + strings.Repeat(`}`, 50) + `}`,
	}

	r := rand.New(rand.NewSource(42))

	for i := 0; i < 1000; i++ {
		base := payloadTemplates[i%len(payloadTemplates)]
		currentPayload = base + fmt.Sprintf(" /* fuzz_seed_%d_%d */", i, r.Intn(99999))

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on fuzz payload iteration %d: %v", i, r)
				}
			}()

			srv, _ := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
			if srv.MCPConfidence == types.ConfidenceConfirmed {
				t.Errorf("fuzz payload %d incorrectly marked Confirmed", i)
			}
		}()
	}
}

// TestHangingServerTimeoutResilience verifies clean timeout enforcement against slow/hanging servers.
func TestHangingServerTimeoutResilience(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(`{"jsonrpc":`))
			f.Flush()
		}
		time.Sleep(3 * time.Second)
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	configuredTimeout := 200 * time.Millisecond
	d := NewDetector(configuredTimeout)

	start := time.Now()
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceNone {
		t.Errorf("expected ConfidenceNone for hanging server, got %v", srv.MCPConfidence)
	}

	maxAllowedTime := configuredTimeout + 250*time.Millisecond
	t.Logf("Configured timeout: %v, Actual elapsed time: %v, Max allowed: %v", configuredTimeout, elapsed, maxAllowedTime)

	if elapsed > maxAllowedTime {
		t.Errorf("detector failed to enforce timeout on hanging server! Elapsed %v > Max %v", elapsed, maxAllowedTime)
	}
}

// TestDetector_AuthOnInitializeHandshake asserts 401/403 responses with WWW-Authenticate or JSON body on initialize are classified as ConfidenceUnverifiableProtected.
func TestDetector_AuthOnInitializeHandshake(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-server"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Authentication required"}`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(500 * time.Millisecond)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceUnverifiableProtected {
		t.Fatalf("expected ConfidenceUnverifiableProtected for auth-gated initialize probe, got %v", srv.MCPConfidence)
	}

	t.Logf("Auth-gated initialize handshake test: PASS (Classified as %s)", srv.MCPConfidence)
}

// TestDetector_AuthNonMCPTrap_HTMLLoginPage asserts 401 responses with HTML login page and no WWW-Authenticate header remain ConfidenceNone.
func TestDetector_AuthNonMCPTrap_HTMLLoginPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><body><h1>401 Unauthorized - Admin Portal Login</h1></body></html>`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(500 * time.Millisecond)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceNone {
		t.Fatalf("VIOLATION: Expected ConfidenceNone for HTML login page trap, got %v", srv.MCPConfidence)
	}

	t.Logf("HTML Login Trap False-Positive Audit: PASS (Classified as %s)", srv.MCPConfidence)
}


// TestDetector_HTTPSServerDetection asserts that TLS/HTTPS MCP servers with self-signed certs are detected as HTTPS.
func TestDetector_HTTPSServerDetection(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		bodyStr := string(buf[:n])
		if strings.Contains(bodyStr, "tools/list") {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"tls_tool"}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"tls-mcp","version":"1.0.0"}}}`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(1 * time.Second)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceConfirmed {
		t.Errorf("expected ConfidenceConfirmed for TLS MCP server, got %v", srv.MCPConfidence)
	}
	if srv.TransportSecurity != types.TransportSecurityHTTPS {
		t.Errorf("expected TransportSecurityHTTPS for TLS MCP server, got %q", srv.TransportSecurity)
	}
}

// TestDetector_TransportSecurityPlaintext asserts that standard HTTP MCP servers are detected as plaintext HTTP.
func TestDetector_TransportSecurityPlaintext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		bodyStr := string(buf[:n])
		if strings.Contains(bodyStr, "tools/list") {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}}`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(1 * time.Second)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.TransportSecurity != types.TransportSecurityPlaintext {
		t.Errorf("expected TransportSecurityPlaintext for HTTP MCP server, got %q", srv.TransportSecurity)
	}
}

// TestParameterShapeDangerDetection verifies exact/tokenized parameter matching, array types, missing types, and false-positive prevention.
func TestParameterShapeDangerDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf := make([]byte, 2048)
		n, _ := r.Body.Read(buf)
		bodyStr := string(buf[:n])

		if strings.Contains(bodyStr, "tools/list") {
			_, _ = w.Write([]byte(`{
				"jsonrpc": "2.0",
				"id": 2,
				"result": {
					"tools": [
						{
							"name": "run_task",
							"description": "Executes a generic background task",
							"inputSchema": {
								"type": "object",
								"properties": {
									"command": { "type": "string" },
									"zip_code": { "type": "string" },
									"format": { "type": "string", "enum": ["json", "text"] },
									"timeout_sec": { "type": "integer" }
								}
							}
						},
						{
							"name": "file_reader",
							"description": "Reads file contents",
							"inputSchema": {
								"type": "object",
								"properties": {
									"filepath": { "type": ["string", "null"] },
									"status_code": { "type": "string" }
								}
							}
						},
						{
							"name": "db_client",
							"description": "Executes query",
							"inputSchema": {
								"type": "object",
								"properties": {
									"sql_query": {}
								}
							}
						}
					]
				}
			}`))
			return
		}

		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}}}}`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(1 * time.Second)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceConfirmed {
		t.Fatalf("expected ConfidenceConfirmed, got %v", srv.MCPConfidence)
	}

	if len(srv.DangerousParams) != 3 {
		t.Fatalf("expected exactly 3 dangerous params, got %d: %+v", len(srv.DangerousParams), srv.DangerousParams)
	}

	flaggedMap := make(map[string]types.DangerousParameter)
	for _, dp := range srv.DangerousParams {
		flaggedMap[dp.ToolName+"."+dp.ParamName] = dp
	}

	// 1. run_task.command -> flagged as string
	if dp, ok := flaggedMap["run_task.command"]; !ok || dp.ParamType != "string" {
		t.Errorf("expected run_task.command flagged with type string, got: %+v", dp)
	}

	// 2. file_reader.filepath -> flagged as string|null
	if dp, ok := flaggedMap["file_reader.filepath"]; !ok || dp.ParamType != "string|null" {
		t.Errorf("expected file_reader.filepath flagged with type string|null, got: %+v", dp)
	}

	// 3. db_client.sql_query -> flagged as any (missing type)
	if dp, ok := flaggedMap["db_client.sql_query"]; !ok || dp.ParamType != "any" {
		t.Errorf("expected db_client.sql_query flagged with type any, got: %+v", dp)
	}

	// Assert safe non-system parameters were NOT flagged
	if _, ok := flaggedMap["run_task.zip_code"]; ok {
		t.Errorf("FALSE POSITIVE: zip_code was wrongly flagged")
	}
	if _, ok := flaggedMap["file_reader.status_code"]; ok {
		t.Errorf("FALSE POSITIVE: status_code was wrongly flagged")
	}
	if _, ok := flaggedMap["run_task.format"]; ok {
		t.Errorf("FALSE POSITIVE: enum-constrained format was wrongly flagged")
	}
	if _, ok := flaggedMap["run_task.timeout_sec"]; ok {
		t.Errorf("FALSE POSITIVE: integer timeout_sec was wrongly flagged")
	}
}

// TestComputeToolDefinitionHash_CanonicalOrderInvariance asserts that tool definitions produce the exact same SHA-256 hash regardless of tool array order in the JSON response.
func TestComputeToolDefinitionHash_CanonicalOrderInvariance(t *testing.T) {
	respA := []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"tools": [
				{ "name": "alpha", "description": "First tool", "inputSchema": { "type": "object", "properties": { "cmd": { "type": "string" } } } },
				{ "name": "beta", "description": "Second tool", "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } } }
			]
		}
	}`)

	respB := []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"tools": [
				{ "name": "beta", "description": "Second tool", "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } } },
				{ "name": "alpha", "description": "First tool", "inputSchema": { "type": "object", "properties": { "cmd": { "type": "string" } } } }
			]
		}
	}`)

	hashA := computeToolDefinitionHash(respA)
	hashB := computeToolDefinitionHash(respB)

	if hashA == "" || hashB == "" {
		t.Fatalf("expected non-empty hashes, got hashA=%q, hashB=%q", hashA, hashB)
	}

	if hashA != hashB {
		t.Errorf("expected deterministic hash equality regardless of tool order: hashA=%s, hashB=%s", hashA, hashB)
	}
}

// TestComputeToolDefinitionHash_Mutation asserts that modifying a tool's description or schema alters the SHA-256 digest.
func TestComputeToolDefinitionHash_Mutation(t *testing.T) {
	original := []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"tools": [
				{ "name": "run_task", "description": "Original description", "inputSchema": { "type": "object" } }
			]
		}
	}`)

	mutated := []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"result": {
			"tools": [
				{ "name": "run_task", "description": "Mutated injected description", "inputSchema": { "type": "object" } }
			]
		}
	}`)

	hashOrig := computeToolDefinitionHash(original)
	hashMut := computeToolDefinitionHash(mutated)

	if hashOrig == hashMut {
		t.Errorf("expected different hashes for mutated tool definition, but both were %q", hashOrig)
	}
}

func netSplitHostPort(rawURL string) (string, string, error) {
	trimmed := strings.TrimPrefix(rawURL, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		return "127.0.0.1", "80", nil
	}
	return parts[0], parts[1], nil
}
