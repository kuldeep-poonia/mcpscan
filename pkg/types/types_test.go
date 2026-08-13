package types

import (
	"testing"
	"time"
)

// TestCalculateSummaryCounts_MultiCategoryBatch tests aggregated counting across all 4 MCP confidence categories and protected risk breakdown.
func TestCalculateSummaryCounts_MultiCategoryBatch(t *testing.T) {
	servers := []DiscoveredServer{
		{
			IP:            "127.0.0.1",
			Port:          8000,
			MCPConfidence: ConfidenceConfirmed,
			AuthStatus:    AuthUnprotected,
			RiskLevel:     RiskHigh,
			DetectedAt:    time.Now().UTC(),
		},
		{
			IP:            "127.0.0.1",
			Port:          8001,
			MCPConfidence: ConfidenceConfirmed,
			AuthStatus:    AuthProtected,
			RiskLevel:     RiskLow,
			DetectedAt:    time.Now().UTC(),
		},
		{
			IP:            "127.0.0.1",
			Port:          8002,
			MCPConfidence: ConfidenceLikely,
			AuthStatus:    AuthUnknown,
			RiskLevel:     RiskMedium,
			DetectedAt:    time.Now().UTC(),
		},
		{
			IP:            "127.0.0.1",
			Port:          8003,
			MCPConfidence: ConfidenceUnverifiableProtected,
			AuthStatus:    AuthProtected,
			RiskLevel:     RiskMedium,
			DetectedAt:    time.Now().UTC(),
		},
		{
			IP:            "127.0.0.1",
			Port:          8004,
			MCPConfidence: ConfidenceNone,
			AuthStatus:    AuthUnknown,
			RiskLevel:     RiskLow,
			DetectedAt:    time.Now().UTC(),
		},
	}

	c := CalculateSummaryCounts(servers)

	if c.Confirmed != 2 {
		t.Errorf("expected 2 Confirmed, got %d", c.Confirmed)
	}
	if c.Likely != 1 {
		t.Errorf("expected 1 Likely, got %d", c.Likely)
	}
	if c.Unverifiable != 1 {
		t.Errorf("expected 1 Unverifiable, got %d", c.Unverifiable)
	}
	if c.None != 1 {
		t.Errorf("expected 1 None, got %d", c.None)
	}
	if c.Evaluated != 4 {
		t.Errorf("expected 4 Evaluated (excluding ConfidenceNone), got %d", c.Evaluated)
	}
	if c.Unprotected != 1 {
		t.Errorf("expected 1 Unprotected, got %d", c.Unprotected)
	}
	if c.Protected != 2 {
		t.Errorf("expected 2 Protected, got %d", c.Protected)
	}
	if c.ProtectedLowRisk != 1 {
		t.Errorf("expected 1 ProtectedLowRisk, got %d", c.ProtectedLowRisk)
	}
	if c.ProtectedMediumRisk != 1 {
		t.Errorf("expected 1 ProtectedMediumRisk, got %d", c.ProtectedMediumRisk)
	}
	if c.Unknown != 1 {
		t.Errorf("expected 1 Unknown, got %d", c.Unknown)
	}
	if c.HighRisk != 1 {
		t.Errorf("expected 1 HighRisk, got %d", c.HighRisk)
	}
	if c.MediumRisk != 2 {
		t.Errorf("expected 2 MediumRisk, got %d", c.MediumRisk)
	}
	if c.LowRisk != 1 {
		t.Errorf("expected 1 LowRisk, got %d", c.LowRisk)
	}

	t.Logf("CalculateSummaryCounts multi-category test: PASS (%+v)", c)
}
