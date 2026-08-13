// Package scanner provides target resolution and TCP connect port scanning logic.
package scanner

import (
	"context"
	"errors"

	"mcpscan/pkg/types"
)

// ErrTargetRangeExceeded is returned when the target host count exceeds the allowed limit.
var ErrTargetRangeExceeded = errors.New("target range exceeds maximum allowed host cap (default 1024)")

// Scanner performs target resolution and TCP connect scanning.
type Scanner struct {
	config types.ScanConfig
}

// NewScanner constructs a Scanner instance with the given configuration.
func NewScanner(cfg types.ScanConfig) *Scanner {
	return &Scanner{config: cfg}
}

// ResolveTargets expands CIDRs/IPs into a bounded slice of IP address strings.
func (s *Scanner) ResolveTargets(ctx context.Context) ([]string, error) {
	// Stub implementation for Phase 0 skeleton
	return []string{}, nil
}

// ScanPorts executes a TCP connect scan against the resolved targets.
func (s *Scanner) ScanPorts(ctx context.Context, targets []string, ports []int) ([]types.OpenPort, error) {
	// Stub implementation for Phase 0 skeleton
	return []types.OpenPort{}, nil
}
