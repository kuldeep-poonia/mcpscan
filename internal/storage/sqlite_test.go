package storage

import (
	"context"
	"testing"
)

func TestNewStorage(t *testing.T) {
	s := NewStorage("test_mcpscan.db")
	if s == nil {
		t.Fatal("expected non-nil storage")
	}

	err := s.InitSchema(context.Background())
	if err != nil {
		t.Fatalf("unexpected error initializing schema stub: %v", err)
	}
}
