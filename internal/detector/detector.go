// Package detector implements the 3-layer verification strategy to identify genuine HTTP MCP servers.
package detector

import (
	"context"
	"time"

	"mcpscan/pkg/types"
)

// Detector performs multi-layer MCP verification on open ports.
type Detector struct {
	timeout time.Duration
}

// NewDetector creates a new Detector instance.
func NewDetector(timeout time.Duration) *Detector {
	return &Detector{timeout: timeout}
}

// DetectPort evaluates a single host/port for MCP protocol compliance.
func (d *Detector) DetectPort(ctx context.Context, target types.OpenPort) (types.DiscoveredServer, error) {
	// Stub implementation for Phase 0 skeleton
	return types.DiscoveredServer{
		IP:            target.IP,
		Port:          target.Port,
		MCPConfidence: types.ConfidenceNone,
		DetectedAt:    time.Now().UTC(),
	}, nil
}

// DetectBatch evaluates a list of open ports sequentially or concurrently.
func (d *Detector) DetectBatch(ctx context.Context, openPorts []types.OpenPort) ([]types.DiscoveredServer, error) {
	results := make([]types.DiscoveredServer, 0, len(openPorts))
	for _, port := range openPorts {
		srv, err := d.DetectPort(ctx, port)
		if err != nil {
			continue
		}
		results = append(results, srv)
	}
	return results, nil
}
