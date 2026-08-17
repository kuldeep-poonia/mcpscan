// Package storage manages local SQLite persistence for scan results.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

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
		transport TEXT NOT NULL DEFAULT 'http',
		transport_security TEXT NOT NULL DEFAULT 'not evaluated',
		mcp_confidence TEXT NOT NULL,
		protocol_version TEXT NOT NULL,
		auth_status TEXT NOT NULL,
		auth_confidence TEXT NOT NULL,
		risk_level TEXT NOT NULL,
		detected_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS stdio_discovered_servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		source_tool TEXT NOT NULL,
		config_file TEXT NOT NULL,
		server_name TEXT NOT NULL,
		command TEXT NOT NULL,
		args_summary TEXT,
		has_env_block INTEGER NOT NULL,
		mcp_confidence TEXT NOT NULL,
		process_match_found INTEGER NOT NULL,
		matched_pid INTEGER,
		detected_at TEXT NOT NULL,
		FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	`

	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initializing schema: %w", err)
	}

	// Gracefully apply column additions for pre-existing databases
	_, _ = db.ExecContext(ctx, "ALTER TABLE discovered_servers ADD COLUMN transport TEXT NOT NULL DEFAULT 'http';")
	_, _ = db.ExecContext(ctx, "ALTER TABLE discovered_servers ADD COLUMN transport_security TEXT NOT NULL DEFAULT 'not evaluated';")

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
	INSERT INTO discovered_servers (scan_id, ip, port, transport, transport_security, mcp_confidence, protocol_version, auth_status, auth_confidence, risk_level, detected_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	stmt, err := tx.PrepareContext(ctx, serverQuery)
	if err != nil {
		return fmt.Errorf("preparing server insert: %w", err)
	}
	defer stmt.Close()

	for i := range servers {
		servers[i].ScanID = scanID
		if servers[i].Transport == "" {
			servers[i].Transport = types.TransportHTTP
		}
		if servers[i].TransportSecurity == "" {
			servers[i].TransportSecurity = types.TransportSecurityNotEvaluated
		}
		_, err := stmt.ExecContext(ctx,
			scanID,
			servers[i].IP,
			servers[i].Port,
			string(servers[i].Transport),
			string(servers[i].TransportSecurity),
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

// SaveStdioDiscoveredServers persists a batch of stdio discovered servers for an existing scan ID.
func (s *Storage) SaveStdioDiscoveredServers(ctx context.Context, scanID int64, servers []types.StdioDiscoveredServer) error {
	if len(servers) == 0 {
		return nil
	}

	db, err := s.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning stdio transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
	INSERT INTO stdio_discovered_servers (scan_id, source_tool, config_file, server_name, command, args_summary, has_env_block, mcp_confidence, process_match_found, matched_pid, detected_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("preparing stdio server insert: %w", err)
	}
	defer stmt.Close()

	for i := range servers {
		servers[i].ScanID = scanID
		hasEnvInt := 0
		if servers[i].HasEnvBlock {
			hasEnvInt = 1
		}
		procMatchInt := 0
		if servers[i].ProcessMatchFound {
			procMatchInt = 1
		}

		var pidVal interface{}
		if servers[i].ProcessMatchFound && servers[i].MatchedPID > 0 {
			pidVal = servers[i].MatchedPID
		} else {
			pidVal = nil
		}

		_, err := stmt.ExecContext(ctx,
			scanID,
			servers[i].SourceTool,
			servers[i].ConfigFile,
			servers[i].ServerName,
			servers[i].Command,
			servers[i].ArgsSummary,
			hasEnvInt,
			string(servers[i].MCPConfidence),
			procMatchInt,
			pidVal,
			servers[i].DetectedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
		)
		if err != nil {
			return fmt.Errorf("inserting stdio server: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing stdio transaction: %w", err)
	}

	s.restrictFilePermissions()
	return nil
}

// GetStdioDiscoveredServers retrieves all stdio servers associated with a specific scan ID.
func (s *Storage) GetStdioDiscoveredServers(ctx context.Context, scanID int64) ([]types.StdioDiscoveredServer, error) {
	db, err := s.openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `
	SELECT id, scan_id, source_tool, config_file, server_name, command, args_summary, has_env_block, mcp_confidence, process_match_found, matched_pid, detected_at
	FROM stdio_discovered_servers
	WHERE scan_id = ?
	ORDER BY id ASC;
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("querying stdio servers: %w", err)
	}
	defer rows.Close()

	var servers []types.StdioDiscoveredServer
	for rows.Next() {
		var srv types.StdioDiscoveredServer
		var hasEnvInt, procMatchInt int
		var pidNull sql.NullInt64
		var mcpConf, detTimeStr string

		if err := rows.Scan(
			&srv.ID,
			&srv.ScanID,
			&srv.SourceTool,
			&srv.ConfigFile,
			&srv.ServerName,
			&srv.Command,
			&srv.ArgsSummary,
			&hasEnvInt,
			&mcpConf,
			&procMatchInt,
			&pidNull,
			&detTimeStr,
		); err != nil {
			return nil, fmt.Errorf("scanning stdio server row: %w", err)
		}

		srv.HasEnvBlock = (hasEnvInt == 1)
		srv.ProcessMatchFound = (procMatchInt == 1)
		srv.MCPConfidence = types.MCPConfidence(mcpConf)
		if pidNull.Valid {
			srv.MatchedPID = int(pidNull.Int64)
		}
		if t, err := time.Parse(time.RFC3339Nano, detTimeStr); err == nil {
			srv.DetectedAt = t
		} else if t, err := time.Parse(time.RFC3339, detTimeStr); err == nil {
			srv.DetectedAt = t
		}
		servers = append(servers, srv)
	}

	return servers, nil
}

// GetLastScan retrieves the most recent scan record and its discovered HTTP and Stdio servers.
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

	if t, err := time.Parse(time.RFC3339Nano, startedStr); err == nil {
		record.StartedAt = t
	} else if t, err := time.Parse(time.RFC3339, startedStr); err == nil {
		record.StartedAt = t
	}

	if t, err := time.Parse(time.RFC3339Nano, endedStr); err == nil {
		record.EndedAt = t
	} else if t, err := time.Parse(time.RFC3339, endedStr); err == nil {
		record.EndedAt = t
	}

	return s.getServersForScan(ctx, db, &record)
}

// getServersForScan queries discovered servers associated with a specific scan ID.
func (s *Storage) getServersForScan(ctx context.Context, db *sql.DB, record *types.ScanRecord) (*types.ScanRecord, []types.DiscoveredServer, error) {
	rows, err := db.QueryContext(ctx, `
	SELECT id, scan_id, ip, port, transport, transport_security, mcp_confidence, protocol_version, auth_status, auth_confidence, risk_level, detected_at
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
		var transportStr, transSecStr, mcpConf, authStat, authConf, riskLvl, detTimeStr string

		if err := rows.Scan(&srv.ID, &srv.ScanID, &srv.IP, &srv.Port, &transportStr, &transSecStr, &mcpConf, &srv.ProtocolVersion, &authStat, &authConf, &riskLvl, &detTimeStr); err != nil {
			return nil, nil, fmt.Errorf("scanning server row: %w", err)
		}

		srv.Transport = types.TransportType(transportStr)
		if srv.Transport == "" {
			srv.Transport = types.TransportHTTP
		}
		srv.TransportSecurity = types.TransportSecurity(transSecStr)
		if srv.TransportSecurity == "" {
			srv.TransportSecurity = types.TransportSecurityNotEvaluated
		}
		srv.MCPConfidence = types.MCPConfidence(mcpConf)
		srv.AuthStatus = types.AuthStatus(authStat)
		srv.AuthConfidence = types.AuthConfidence(authConf)
		srv.RiskLevel = types.RiskLevel(riskLvl)
		if t, err := time.Parse(time.RFC3339Nano, detTimeStr); err == nil {
			srv.DetectedAt = t
		} else if t, err := time.Parse(time.RFC3339, detTimeStr); err == nil {
			srv.DetectedAt = t
		}
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
