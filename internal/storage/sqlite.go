// Package storage manages local SQLite persistence for scan results.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	_ "modernc.org/sqlite"

	"mcpscan/pkg/types"
)

// Storage handles reading and writing scan results to an embedded SQLite database.
type Storage struct {
	dbPath string
}

// NewStorage initializes a Storage instance pointed at the specified SQLite database file.
func NewStorage(dbPath string) *Storage {
	if dbPath == "" {
		dbPath = "mcpscan.db"
	}
	return &Storage{dbPath: dbPath}
}

// openDB opens an SQLite connection and explicitly enables foreign key constraints.
func (s *Storage) openDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", s.dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite db: %w", err)
	}

	// Hard requirement: PRAGMA foreign_keys = ON must be set per-connection
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	return db, nil
}

// InitSchema creates the `scans` and `discovered_servers` tables if they do not exist.
func (s *Storage) InitSchema(ctx context.Context) error {
	db, err := s.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at TEXT NOT NULL,
		ended_at TEXT NOT NULL,
		target_range TEXT NOT NULL,
		total_hosts_scanned INTEGER NOT NULL,
		tool_version TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS discovered_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		mcp_confidence TEXT NOT NULL,
		protocol_version TEXT NOT NULL,
		auth_status TEXT NOT NULL,
		auth_confidence TEXT NOT NULL,
		risk_level TEXT NOT NULL,
		detected_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	`

	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initializing schema: %w", err)
	}

	// Apply file permission hardening
	s.restrictFilePermissions()

	return nil
}

// SaveScan persists a scan run record and its discovered servers in an atomic transaction.
func (s *Storage) SaveScan(ctx context.Context, record *types.ScanRecord, servers []types.DiscoveredServer) error {
	db, err := s.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1. Insert scan record
	scanQuery := `
	INSERT INTO scans (started_at, ended_at, target_range, total_hosts_scanned, tool_version)
	VALUES (?, ?, ?, ?, ?);
	`
	res, err := tx.ExecContext(ctx, scanQuery,
		record.StartedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		record.EndedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		record.TargetRange,
		record.TotalHostsScanned,
		record.ToolVersion,
	)
	if err != nil {
		return fmt.Errorf("inserting scan record: %w", err)
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("getting last insert scan_id: %w", err)
	}
	record.ID = scanID

	// 2. Insert discovered servers
	serverQuery := `
	INSERT INTO discovered_servers (scan_id, ip, port, mcp_confidence, protocol_version, auth_status, auth_confidence, risk_level, detected_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	stmt, err := tx.PrepareContext(ctx, serverQuery)
	if err != nil {
		return fmt.Errorf("preparing server insert: %w", err)
	}
	defer stmt.Close()

	for i := range servers {
		servers[i].ScanID = scanID
		_, err := stmt.ExecContext(ctx,
			scanID,
			servers[i].IP,
			servers[i].Port,
			string(servers[i].MCPConfidence),
			servers[i].ProtocolVersion,
			string(servers[i].AuthStatus),
			string(servers[i].AuthConfidence),
			string(servers[i].RiskLevel),
			servers[i].DetectedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		)
		if err != nil {
			return fmt.Errorf("inserting discovered server: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	// Apply file permission hardening
	s.restrictFilePermissions()

	return nil
}

// GetLastScan retrieves the most recent scan record and its discovered servers.
func (s *Storage) GetLastScan(ctx context.Context) (*types.ScanRecord, []types.DiscoveredServer, error) {
	db, err := s.openDB()
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()

	row := db.QueryRowContext(ctx, `
	SELECT id, started_at, ended_at, target_range, total_hosts_scanned, tool_version
	FROM scans
	ORDER BY id DESC
	LIMIT 1;
	`)

	var record types.ScanRecord
	var startedStr, endedStr string
	err = row.Scan(&record.ID, &startedStr, &endedStr, &record.TargetRange, &record.TotalHostsScanned, &record.ToolVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, []types.DiscoveredServer{}, nil
		}
		return nil, nil, fmt.Errorf("querying last scan: %w", err)
	}

	return s.getServersForScan(ctx, db, &record)
}

// getServersForScan queries discovered servers associated with a specific scan ID.
func (s *Storage) getServersForScan(ctx context.Context, db *sql.DB, record *types.ScanRecord) (*types.ScanRecord, []types.DiscoveredServer, error) {
	rows, err := db.QueryContext(ctx, `
	SELECT id, scan_id, ip, port, mcp_confidence, protocol_version, auth_status, auth_confidence, risk_level, detected_at
	FROM discovered_servers
	WHERE scan_id = ?
	ORDER BY id ASC;
	`, record.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("querying discovered servers: %w", err)
	}
	defer rows.Close()

	var servers []types.DiscoveredServer
	for rows.Next() {
		var srv types.DiscoveredServer
		var mcpConf, authStat, authConf, riskLvl, detTimeStr string

		if err := rows.Scan(&srv.ID, &srv.ScanID, &srv.IP, &srv.Port, &mcpConf, &srv.ProtocolVersion, &authStat, &authConf, &riskLvl, &detTimeStr); err != nil {
			return nil, nil, fmt.Errorf("scanning server row: %w", err)
		}

		srv.MCPConfidence = types.MCPConfidence(mcpConf)
		srv.AuthStatus = types.AuthStatus(authStat)
		srv.AuthConfidence = types.AuthConfidence(authConf)
		srv.RiskLevel = types.RiskLevel(riskLvl)
		servers = append(servers, srv)
	}

	return record, servers, nil
}

// restrictFilePermissions applies 0600 permissions on Unix and attempts icacls ACL restriction on Windows.
// Gracefully handles permission restriction failures without crashing the application.
func (s *Storage) restrictFilePermissions() {
	if _, err := os.Stat(s.dbPath); err != nil {
		return
	}

	// 1. Unix standard permission
	_ = os.Chmod(s.dbPath, 0600)

	// 2. Windows ACL hardening (best effort)
	if runtime.GOOS == "windows" {
		username := os.Getenv("USERNAME")
		if username != "" {
			// Strip inherited permissions and grant full control to current user
			cmd := exec.Command("icacls", s.dbPath, "/inheritance:r", "/grant:r", username+":F")
			if err := cmd.Run(); err != nil {
				// Log warning gracefully without crashing scan
				fmt.Fprintf(os.Stderr, "[WARNING] Unable to restrict Windows ACLs on %s: %v\n", s.dbPath, err)
			}
		}
	}
}
