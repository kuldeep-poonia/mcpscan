// Package storage manages local SQLite persistence for scan results.
package storage

import (
	"context"

	"mcpscan/pkg/types"
)

// Storage handles reading and writing scan results to an embedded SQLite database.
type Storage struct {
	dbPath string
}

// NewStorage initializes a Storage instance pointed at the specified SQLite database file.
func NewStorage(dbPath string) *Storage {
	return &Storage{dbPath: dbPath}
}

// InitSchema creates the `scans` and `discovered_servers` tables if they do not exist.
func (s *Storage) InitSchema(ctx context.Context) error {
	// Stub implementation for Phase 0 skeleton
	return nil
}

// SaveScan persists a scan run record and its discovered servers.
func (s *Storage) SaveScan(ctx context.Context, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	// Stub implementation for Phase 0 skeleton
	return nil
}

// GetLastScan retrieves the most recent scan record and results.
func (s *Storage) GetLastScan(ctx context.Context) (*types.ScanRecord, []types.DiscoveredServer, error) {
	// Stub implementation for Phase 0 skeleton
	return &types.ScanRecord{}, []types.DiscoveredServer{}, nil
}
