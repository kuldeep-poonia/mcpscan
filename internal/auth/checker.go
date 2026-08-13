// Package auth implements non-destructive, single-request authentication status checking.
package auth

import (
	"context"
	"time"

	"mcpscan/pkg/types"
)

// Checker performs unauthenticated probe requests against detected MCP servers.
type Checker struct {
	timeout time.Duration
}

// NewChecker constructs a Checker instance with the specified timeout.
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{timeout: timeout}
}

// CheckAuth performs exactly ONE unauthenticated probe request to check auth status.
// Hard constraint: Must never retry, brute-force, or send multiple requests.
func (c *Checker) CheckAuth(ctx context.Context, server types.DiscoveredServer) (types.DiscoveredServer, error) {
	// Stub implementation for Phase 0 skeleton
	server.AuthStatus = types.AuthUnknown
	server.AuthConfidence = types.AuthConfidenceLow
	server.RiskLevel = types.RiskLow
	return server, nil
}
