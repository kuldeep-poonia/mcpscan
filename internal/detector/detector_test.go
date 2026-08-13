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

func netSplitHostPort(rawURL string) (string, string, error) {
	trimmed := strings.TrimPrefix(rawURL, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		return "127.0.0.1", "80", nil
	}
	return parts[0], parts[1], nil
}
