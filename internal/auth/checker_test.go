package auth

import (
	"context"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

func TestNewChecker(t *testing.T) {
	c := NewChecker(2 * time.Second)
	if c == nil {
		t.Fatal("expected non-nil checker")
	}

	srv := types.DiscoveredServer{IP: "127.0.0.1", Port: 8080}
	res, err := c.CheckAuth(context.Background(), srv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.AuthStatus != types.AuthUnknown {
		t.Errorf("expected AuthUnknown in stub, got %v", res.AuthStatus)
	}
}
