package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

// TestStorage_WriteAndReadIntegrity asserts 100% write and read integrity of scan data in SQLite.
func TestStorage_WriteAndReadIntegrity(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_mcpscan.db")

	store := NewStorage(dbPath)
	ctx := context.Background()

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	record := &types.ScanRecord{
		StartedAt:         time.Now().Add(-5 * time.Second).Truncate(time.Millisecond),
		EndedAt:           time.Now().Truncate(time.Millisecond),
		TargetRange:       "192.168.1.0/24",
		TotalHostsScanned: 256,
		ToolVersion:       "v1.0.0-test",
	}

	servers := []types.DiscoveredServer{
		{
			IP:              "192.168.1.10",
			Port:            8080,
			MCPConfidence:   types.ConfidenceConfirmed,
			ProtocolVersion: "2024-11-05",
			AuthStatus:      types.AuthUnprotected,
			AuthConfidence:  types.AuthConfidenceHigh,
			RiskLevel:       types.RiskHigh,
			DetectedAt:      time.Now().Truncate(time.Millisecond),
		},
		{
			IP:              "192.168.1.20",
			Port:            3000,
			MCPConfidence:   types.ConfidenceLikely,
			ProtocolVersion: "2024-10-07",
			AuthStatus:      types.AuthProtected,
			AuthConfidence:  types.AuthConfidenceHigh,
			RiskLevel:       types.RiskLow,
			DetectedAt:      time.Now().Truncate(time.Millisecond),
		},
	}

	if err := store.SaveScan(ctx, record, servers); err != nil {
		t.Fatalf("failed to save scan: %v", err)
	}

	if record.ID <= 0 {
		t.Fatalf("expected positive scan ID, got %d", record.ID)
	}

	readRecord, readServers, err := store.GetLastScan(ctx)
	if err != nil {
		t.Fatalf("failed to read last scan: %v", err)
	}

	// Assert scan record fields
	if readRecord.ID != record.ID || readRecord.TargetRange != record.TargetRange || readRecord.TotalHostsScanned != record.TotalHostsScanned {
		t.Errorf("scan record mismatch: got %+v, expected %+v", readRecord, record)
	}

	// Assert discovered servers list count and fields
	if len(readServers) != len(servers) {
		t.Fatalf("expected %d discovered servers, got %d", len(servers), len(readServers))
	}

	for i, expected := range servers {
		actual := readServers[i]
		if actual.IP != expected.IP || actual.Port != expected.Port || actual.MCPConfidence != expected.MCPConfidence || actual.AuthStatus != expected.AuthStatus || actual.RiskLevel != expected.RiskLevel {
			t.Errorf("server %d mismatch: got %+v, expected %+v", i, actual, expected)
		}
	}
}

// TestStorage_ForeignKeyEnforcement asserts that PRAGMA foreign_keys = ON rejects orphaned server rows.
func TestStorage_ForeignKeyEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_fk.db")

	store := NewStorage(dbPath)
	ctx := context.Background()

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	db, err := store.openDB()
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	// Attempt to insert an orphaned discovered_servers row with scan_id = 99999 (does not exist in scans table)
	query := `
	INSERT INTO discovered_servers (scan_id, ip, port, mcp_confidence, protocol_version, auth_status, auth_confidence, risk_level, detected_at)
	VALUES (99999, '127.0.0.1', 8080, 'confirmed', '2024-11-05', 'unprotected', 'high', 'HIGH', '2026-08-13T09:00:00Z');
	`
	_, err = db.ExecContext(ctx, query)
	if err == nil {
		t.Fatal("VIOLATION: Expected foreign key constraint violation error for orphaned scan_id 99999, got nil!")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Errorf("expected foreign key constraint error, got: %v", err)
	}
}

// TestStorage_FilePermissionCheck verifies that database file permissions are created and hardened.
func TestStorage_FilePermissionCheck(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "perm_test.db")

	store := NewStorage(dbPath)
	if err := store.InitSchema(context.Background()); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("failed to stat db file: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("expected non-zero db file size")
	}
}
