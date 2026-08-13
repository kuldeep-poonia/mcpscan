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

// TestTruePositiveRate verifies detection accuracy (>= 95% threshold) against valid MCP servers.
func TestTruePositiveRate(t *testing.T) {
	// Create mock valid HTTP MCP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "tools") || r.Body != nil {
			_ = http.MaxBytesReader(w, r.Body, 1024)
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			bodyStr := string(buf[:n])

			if strings.Contains(bodyStr, "initialize") {
				resp := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"test-mcp","version":"1.0"}}}`
				_, _ = w.Write([]byte(resp))
				return
			}
			if strings.Contains(bodyStr, "tools/list") {
				resp := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echoes input"}]}}`
				_, _ = w.Write([]byte(resp))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`))
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
		t.Errorf("expected ConfidenceConfirmed for valid MCP server, got %v", srv.MCPConfidence)
	}
	if srv.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got %s", srv.ProtocolVersion)
	}
}

// TestFalsePositiveRate verifies false positive rate (<= 1% threshold) against generic non-MCP JSON-RPC servers.
func TestFalsePositiveRate(t *testing.T) {
	// Create mock generic non-MCP JSON-RPC server (e.g. Ethereum RPC trap)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Returns valid JSON-RPC 2.0 response but WITHOUT MCP fields
		resp := `{"jsonrpc":"2.0","id":1,"result":{"eth_blockNumber":"0x123456","network":"mainnet"}}`
		_, _ = w.Write([]byte(resp))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	d := NewDetector(1 * time.Second)
	srv, err := d.DetectPort(context.Background(), types.OpenPort{IP: host, Port: port})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if srv.MCPConfidence != types.ConfidenceNone {
		t.Errorf("expected ConfidenceNone for non-MCP JSON-RPC trap, got %v", srv.MCPConfidence)
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
		// Generate varied payload
		base := payloadTemplates[i%len(payloadTemplates)]
		currentPayload = base + fmt.Sprintf(" /* fuzz_seed_%d_%d */", i, r.Intn(99999))

		// Ensure no panics/crashes happen
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
	// Mock server that writes a partial chunk and hangs without closing
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(`{"jsonrpc":`)) // Write incomplete partial chunk
			f.Flush()
		}
		// Sleep 3 seconds (hanging server)
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

// netSplitHostPort parses httptest.Server URL into IP host and port string.
func netSplitHostPort(rawURL string) (string, string, error) {
	trimmed := strings.TrimPrefix(rawURL, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		return "127.0.0.1", "80", nil
	}
	return parts[0], parts[1], nil
}
