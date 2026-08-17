package auth

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

// TestAuthClassificationAccuracy evaluates classification accuracy across 9 distinct server fixtures (>= 98% threshold).
func TestAuthClassificationAccuracy(t *testing.T) {
	type testCase struct {
		name               string
		handler            http.HandlerFunc
		expectedStatus     types.AuthStatus
		expectedConfidence types.AuthConfidence
		expectedRisk       types.RiskLevel
	}

	testCases := []testCase{
		// --- Unprotected Category (3 variations) ---
		{
			name: "Unprotected 1: 200 OK with tools/list result",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{"tools":[{"name":"test"}]}}`))
			},
			expectedStatus:     types.AuthUnprotected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskHigh,
		},
		{
			name: "Unprotected 2: 200 OK with ping result",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{}}`))
			},
			expectedStatus:     types.AuthUnprotected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskHigh,
		},
		{
			name: "Unprotected 3: 200 OK with initialize result",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{"protocolVersion":"2024-11-05"}}`))
			},
			expectedStatus:     types.AuthUnprotected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskHigh,
		},

		// --- Protected Category (3 variations) ---
		{
			name: "Protected 1: 401 Unauthorized with WWW-Authenticate header",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", "Bearer realm=\"mcp-server\"")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			},
			expectedStatus:     types.AuthProtected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskLow,
		},
		{
			name: "Protected 2: 403 Forbidden with JSON error body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"error":{"code":-32000,"message":"Authentication required"}}`))
			},
			expectedStatus:     types.AuthProtected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskLow,
		},
		{
			name: "Protected 3: 401 Unauthorized raw status without headers",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			expectedStatus:     types.AuthProtected,
			expectedConfidence: types.AuthConfidenceHigh,
			expectedRisk:       types.RiskLow,
		},

		// --- Ambiguous Category (3 variations) ---
		{
			name: "Ambiguous 1: 500 Internal Server Error HTML page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("<html><body>500 Internal Error</body></html>"))
			},
			expectedStatus:     types.AuthUnknown,
			expectedConfidence: types.AuthConfidenceLow,
			expectedRisk:       types.RiskMedium,
		},
		{
			name: "Ambiguous 2: 404 Not Found plain text",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("404 page not found"))
			},
			expectedStatus:     types.AuthUnknown,
			expectedConfidence: types.AuthConfidenceLow,
			expectedRisk:       types.RiskMedium,
		},
		{
			name: "Ambiguous 3: 200 OK with corrupted non-JSON body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("CORRUPTED_NON_JSON_DATA"))
			},
			expectedStatus:     types.AuthUnknown,
			expectedConfidence: types.AuthConfidenceLow,
			expectedRisk:       types.RiskMedium,
		},
	}

	c := NewChecker(1 * time.Second)
	correctCount := 0

	for i, tc := range testCases {
		ts := httptest.NewServer(tc.handler)
		host, portStr, _ := netSplitHostPort(ts.URL)
		port, _ := strconv.Atoi(portStr)

		srvInput := types.DiscoveredServer{
			IP:            host,
			Port:          port,
			MCPConfidence: types.ConfidenceConfirmed,
		}

		res, err := c.CheckAuth(context.Background(), srvInput)
		ts.Close()

		if err != nil {
			t.Errorf("[%s] unexpected error: %v", tc.name, err)
			continue
		}

		if res.AuthStatus == tc.expectedStatus && res.AuthConfidence == tc.expectedConfidence && res.RiskLevel == tc.expectedRisk {
			correctCount++
		} else {
			t.Errorf("[%s] MISMATCH! Got Status=%v, Confidence=%v, Risk=%v; Expected Status=%v, Confidence=%v, Risk=%v",
				tc.name, res.AuthStatus, res.AuthConfidence, res.RiskLevel, tc.expectedStatus, tc.expectedConfidence, tc.expectedRisk)
		}
		_ = i
	}

	accuracy := (float64(correctCount) / float64(len(testCases))) * 100.0
	t.Logf("Auth Classification Accuracy across %d distinct fixtures: %.2f%%", len(testCases), accuracy)

	if accuracy < 98.0 {
		t.Errorf("accuracy %.2f%% below 98.0%% threshold", accuracy)
	}
}

// TestSkipAuthForNonMCP asserts that servers with ConfidenceNone receive ZERO HTTP requests during auth checking.
func TestSkipAuthForNonMCP(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	nonMCPServer := types.DiscoveredServer{
		IP:            host,
		Port:          port,
		MCPConfidence: types.ConfidenceNone,
	}

	c := NewChecker(1 * time.Second)
	res, err := c.CheckAuth(context.Background(), nonMCPServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actualRequests := atomic.LoadInt32(&requestCount)
	t.Logf("Requests received for ConfidenceNone server: %d", actualRequests)

	if actualRequests != 0 {
		t.Errorf("VIOLATION: Expected 0 HTTP requests sent to ConfidenceNone server, got %d", actualRequests)
	}

	if res.AuthStatus != types.AuthUnknown {
		t.Errorf("expected AuthUnknown for ConfidenceNone server, got %v", res.AuthStatus)
	}
}

// TestRequestCountDiscipline runs CheckAuthBatch against a multi-server batch and asserts EVERY server received EXACTLY 1 request.
func TestRequestCountDiscipline(t *testing.T) {
	numServers := 5
	servers := make([]types.DiscoveredServer, numServers)
	counters := make([]int32, numServers)
	tsList := make([]*httptest.Server, numServers)

	for i := 0; i < numServers; i++ {
		serverIdx := i
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&counters[serverIdx], 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{}}`))
		}))
		tsList[i] = ts

		host, portStr, _ := netSplitHostPort(ts.URL)
		port, _ := strconv.Atoi(portStr)

		servers[i] = types.DiscoveredServer{
			IP:            host,
			Port:          port,
			MCPConfidence: types.ConfidenceConfirmed,
		}
	}

	c := NewChecker(1 * time.Second)
	_, err := c.CheckAuthBatch(context.Background(), servers)

	for _, ts := range tsList {
		ts.Close()
	}

	if err != nil {
		t.Fatalf("unexpected error running batch auth check: %v", err)
	}

	for i := 0; i < numServers; i++ {
		reqCount := atomic.LoadInt32(&counters[i])
		t.Logf("Server #%d received %d request(s)", i+1, reqCount)
		if reqCount != 1 {
			t.Errorf("VIOLATION: Server #%d received %d request(s); strictly MUST be exactly 1 request", i+1, reqCount)
		}
	}
}

// TestAuthChecker_MalformedFuzzResilience executes 1,000 distinct malformed/hostile HTTP responses against CheckAuth with 0 crashes.
func TestAuthChecker_MalformedFuzzResilience(t *testing.T) {
	var currentPayload string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(currentPayload))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	c := NewChecker(100 * time.Millisecond)

	payloadTemplates := []string{
		`{"jsonrpc":"2.0"}`,
		`{"jsonrpc":"1.0","id":99}`,
		`{"jsonrpc":"2.0","id":null,"result":{}}`,
		`<html><body>Server Error 500</body></html>`,
		`\x00\x01\x02\x03\x04\x05`,
		`{"jsonrpc":"2.0","id":99,"result":12345}`,
		`[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]`,
		`{"a":` + strings.Repeat(`{"b":`, 50) + `1` + strings.Repeat(`}`, 50) + `}`,
	}

	r := rand.New(rand.NewSource(99))

	for i := 0; i < 1000; i++ {
		base := payloadTemplates[i%len(payloadTemplates)]
		currentPayload = base + fmt.Sprintf(" /* auth_fuzz_%d_%d */", i, r.Intn(99999))

		func() {
			defer func() {
				if err := recover(); err != nil {
					t.Fatalf("PANIC on Auth Checker fuzz payload iteration %d: %v", i, err)
				}
			}()

			target := types.DiscoveredServer{
				IP:            host,
				Port:          port,
				MCPConfidence: types.ConfidenceConfirmed,
			}
			_, _ = c.CheckAuth(context.Background(), target)
		}()
	}

	t.Logf("Auth Checker Fuzz Resilience Audit: PASS (0 crashes across 1,000 malformed response payloads)")
}

// TestCheckAuth_UnverifiableProtected asserts ConfidenceUnverifiableProtected results in AuthProtected, AuthConfidenceMedium, and RiskMedium with 0 HTTP requests.
func TestCheckAuth_UnverifiableProtected(t *testing.T) {
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	c := NewChecker(100 * time.Millisecond)
	target := types.DiscoveredServer{
		IP:            host,
		Port:          port,
		MCPConfidence: types.ConfidenceUnverifiableProtected,
	}

	res, err := c.CheckAuth(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&reqCount) != 0 {
		t.Errorf("expected 0 HTTP requests sent for ConfidenceUnverifiableProtected, got %d", atomic.LoadInt32(&reqCount))
	}

	if res.AuthStatus != types.AuthProtected || res.AuthConfidence != types.AuthConfidenceMedium || res.RiskLevel != types.RiskMedium {
		t.Errorf("MISMATCH! Got Status=%v, Confidence=%v, Risk=%v; Expected AuthProtected, AuthConfidenceMedium, RiskMedium",
			res.AuthStatus, res.AuthConfidence, res.RiskLevel)
	}

	t.Logf("UnverifiableProtected Auth Audit: PASS (Status=%v, Confidence=%v, Risk=%v)", res.AuthStatus, res.AuthConfidence, res.RiskLevel)
}

// TestCheckAuth_HTTPSServerExactOneRequest asserts that CheckAuth handles TLS/HTTPS servers and issues exactly 1 request.
func TestCheckAuth_HTTPSServerExactOneRequest(t *testing.T) {
	var reqCount int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{"tools":[]}}`))
	}))
	defer ts.Close()

	host, portStr, _ := netSplitHostPort(ts.URL)
	port, _ := strconv.Atoi(portStr)

	target := types.DiscoveredServer{
		IP:                host,
		Port:              port,
		Transport:         types.TransportHTTP,
		TransportSecurity: types.TransportSecurityHTTPS,
		MCPConfidence:     types.ConfidenceConfirmed,
	}

	c := NewChecker(1 * time.Second)
	res, err := c.CheckAuth(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := atomic.LoadInt32(&reqCount)
	if count != 1 {
		t.Errorf("expected exactly 1 request to HTTPS server, got %d", count)
	}
	if res.AuthStatus != types.AuthUnprotected {
		t.Errorf("expected AuthUnprotected for open HTTPS server, got %v", res.AuthStatus)
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
