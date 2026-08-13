package auth

import (
	"context"
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

	// Clean up servers
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

func netSplitHostPort(rawURL string) (string, string, error) {
	trimmed := strings.TrimPrefix(rawURL, "http://")
	trimmed = strings.TrimPrefix(trimmed, "https://")
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 {
		return "127.0.0.1", "80", nil
	}
	return parts[0], parts[1], nil
}
