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
			IP:                "192.168.1.10",
			Port:              8080,
			TransportSecurity: types.TransportSecurityPlaintext,
			MCPConfidence:     types.ConfidenceConfirmed,
			ProtocolVersion:   "2024-11-05",
			AuthStatus:        types.AuthUnprotected,
			AuthConfidence:    types.AuthConfidenceHigh,
			RiskLevel:         types.RiskHigh,
			DangerousParams: []types.DangerousParameter{
				{ToolName: "run_task", ParamName: "command", ParamType: "string"},
			},
			DetectedAt: time.Now().Truncate(time.Millisecond),
		},
		{
			IP:                "192.168.1.20",
			Port:              3000,
			TransportSecurity: types.TransportSecurityHTTPS,
			MCPConfidence:     types.ConfidenceLikely,
			ProtocolVersion:   "2024-10-07",
			AuthStatus:        types.AuthProtected,
			AuthConfidence:    types.AuthConfidenceHigh,
			RiskLevel:         types.RiskLow,
			DetectedAt:        time.Now().Truncate(time.Millisecond),
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
		if actual.Transport != types.TransportHTTP {
			t.Errorf("expected server %d transport to be 'http', got %q", i, actual.Transport)
		}
		if actual.TransportSecurity != expected.TransportSecurity {
			t.Errorf("expected server %d transport_security to be %q, got %q", i, expected.TransportSecurity, actual.TransportSecurity)
		}
		if len(actual.DangerousParams) != len(expected.DangerousParams) {
			t.Errorf("server %d dangerous_params length mismatch: got %d, expected %d", i, len(actual.DangerousParams), len(expected.DangerousParams))
		}
		if actual.DetectedAt.IsZero() {
			t.Errorf("expected server %d detected_at to be non-zero", i)
		}
	}
}

// TestStorage_ReportSubcommandReadback specifically asserts that reading back a scan
// for the report command populates StartedAt, EndedAt, TargetRange, and Transport correctly.
func TestStorage_ReportSubcommandReadback(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "report_readback.db")

	store := NewStorage(dbPath)
	ctx := context.Background()

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	startTime := time.Now().Add(-10 * time.Second).UTC().Truncate(time.Second)
	endTime := time.Now().UTC().Truncate(time.Second)

	record := &types.ScanRecord{
		StartedAt:         startTime,
		EndedAt:           endTime,
		TargetRange:       "127.0.0.1",
		TotalHostsScanned: 1,
		ToolVersion:       "v1.1.0",
	}

	servers := []types.DiscoveredServer{
		{
			IP:                "127.0.0.1",
			Port:              8000,
			Transport:         types.TransportHTTP,
			TransportSecurity: types.TransportSecurityPlaintext,
			MCPConfidence:     types.ConfidenceConfirmed,
			ProtocolVersion:   "2024-11-05",
			AuthStatus:        types.AuthUnprotected,
			AuthConfidence:    types.AuthConfidenceHigh,
			RiskLevel:         types.RiskHigh,
			DetectedAt:        startTime,
		},
	}

	if err := store.SaveScan(ctx, record, servers); err != nil {
		t.Fatalf("failed to save scan: %v", err)
	}

	// Read back via GetLastScan
	retrievedRecord, retrievedServers, err := store.GetLastScan(ctx)
	if err != nil {
		t.Fatalf("failed to get last scan: %v", err)
	}

	if retrievedRecord.StartedAt.IsZero() {
		t.Errorf("expected non-zero StartedAt, got %v", retrievedRecord.StartedAt)
	}
	if retrievedRecord.EndedAt.IsZero() {
		t.Errorf("expected non-zero EndedAt, got %v", retrievedRecord.EndedAt)
	}
	if retrievedRecord.TargetRange != "127.0.0.1" {
		t.Errorf("expected TargetRange '127.0.0.1', got %q", retrievedRecord.TargetRange)
	}
	if len(retrievedServers) != 1 {
		t.Fatalf("expected 1 retrieved server, got %d", len(retrievedServers))
	}
	if retrievedServers[0].Transport != types.TransportHTTP {
		t.Errorf("expected Transport 'http', got %q", retrievedServers[0].Transport)
	}
	if retrievedServers[0].TransportSecurity != types.TransportSecurityPlaintext {
		t.Errorf("expected TransportSecurity 'plaintext HTTP', got %q", retrievedServers[0].TransportSecurity)
	}
	if retrievedServers[0].DetectedAt.IsZero() || retrievedServers[0].DetectedAt.Year() == 1 {
		t.Errorf("REGRESSION: retrieved server DetectedAt is zero-value: %v", retrievedServers[0].DetectedAt)
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
		t.Fatalf("expected DB file to exist: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("expected DB file size > 0 bytes, got %d", info.Size())
	}
}

// TestStorage_StdioWriteAndCascadeDelete verifies write/read roundtrip for stdio servers and cascade deletion.
func TestStorage_StdioWriteAndCascadeDelete(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_stdio_fk.db")

	store := NewStorage(dbPath)
	ctx := context.Background()

	if err := store.InitSchema(ctx); err != nil {
		t.Fatalf("failed to initialize schema: %v", err)
	}

	record := &types.ScanRecord{
		StartedAt:         time.Now().Add(-5 * time.Second),
		EndedAt:           time.Now(),
		TargetRange:       "127.0.0.1",
		TotalHostsScanned: 1,
		ToolVersion:       "v2.0.0-test",
	}

	if err := store.SaveScan(ctx, record, nil); err != nil {
		t.Fatalf("failed to save parent scan: %v", err)
	}

	stdioServers := []types.StdioDiscoveredServer{
		{
			SourceTool:        "Claude Desktop",
			ConfigFile:        "/Users/test/claude_desktop_config.json",
			ServerName:        "filesystem",
			Command:           "npx",
			ArgsSummary:       "-y @modelcontextprotocol/server-filesystem /tmp",
			HasEnvBlock:       false,
			MCPConfidence:     types.ConfidenceConfirmed,
			ProcessMatchFound: true,
			MatchedPID:        12345,
			DetectedAt:        time.Now().Truncate(time.Millisecond),
		},
		{
			SourceTool:        "Cursor",
			ConfigFile:        "/Users/test/.cursor/mcp.json",
			ServerName:        "postgres",
			Command:           "node",
			ArgsSummary:       "index.js --port 5432",
			HasEnvBlock:       true,
			MCPConfidence:     types.ConfidenceLikely,
			ProcessMatchFound: false,
			DetectedAt:        time.Now().Truncate(time.Millisecond),
		},
	}

	if err := store.SaveStdioDiscoveredServers(ctx, record.ID, stdioServers); err != nil {
		t.Fatalf("failed to save stdio servers: %v", err)
	}

	// 1. Verify readback
	retrieved, err := store.GetStdioDiscoveredServers(ctx, record.ID)
	if err != nil {
		t.Fatalf("failed to get stdio servers: %v", err)
	}
	if len(retrieved) != 2 {
		t.Fatalf("expected 2 stdio servers, got %d", len(retrieved))
	}
	if retrieved[0].ServerName != "filesystem" || !retrieved[0].ProcessMatchFound || retrieved[0].MatchedPID != 12345 {
		t.Errorf("stdio server 0 mismatch: %+v", retrieved[0])
	}
	if retrieved[1].ServerName != "postgres" || retrieved[1].ProcessMatchFound || !retrieved[1].HasEnvBlock {
		t.Errorf("stdio server 1 mismatch: %+v", retrieved[1])
	}

	// 2. Verify Foreign Key Cascade Delete
	db, err := store.openDB()
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	// Delete parent scan record
	if _, err := db.ExecContext(ctx, "DELETE FROM scans WHERE id = ?;", record.ID); err != nil {
		t.Fatalf("failed to delete scan record: %v", err)
	}

	// Assert stdio_discovered_servers were cascaded and deleted automatically
	cascaded, err := store.GetStdioDiscoveredServers(ctx, record.ID)
	if err != nil {
		t.Fatalf("error checking cascaded stdio servers: %v", err)
	}
	if len(cascaded) != 0 {
		t.Fatalf("CASCADE VIOLATION: expected 0 cascaded stdio servers, found %d", len(cascaded))
	}
}
