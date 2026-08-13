package scanner

import (
	"context"
	"testing"

	"mcpscan/pkg/types"
)

func TestNewScanner(t *testing.T) {
	cfg := types.ScanConfig{Concurrency: 10}
	s := NewScanner(cfg)
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}

	targets, err := s.ResolveTargets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error resolving targets: %v", err)
	}
	if len(targets) != 0 {
		t.Errorf("expected empty targets slice in stub, got %d", len(targets))
	}
}
