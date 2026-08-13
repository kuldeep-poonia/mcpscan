package detector

import (
	"context"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector(2 * time.Second)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}

	res, err := d.DetectPort(context.Background(), types.OpenPort{IP: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.MCPConfidence != types.ConfidenceNone {
		t.Errorf("expected ConfidenceNone in stub, got %v", res.MCPConfidence)
	}
}
