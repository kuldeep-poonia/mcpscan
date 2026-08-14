// Package types contains common data structures and models used throughout MCPScan.
package types

import "time"

// MCPConfidence represents the confidence level of MCP protocol detection.
type MCPConfidence string

const (
	ConfidenceConfirmed             MCPConfidence = "confirmed"
	ConfidenceLikely                MCPConfidence = "likely"
	ConfidenceUnverifiableProtected MCPConfidence = "unverifiable_protected"
	ConfidenceNone                  MCPConfidence = "none"
)

// AuthStatus represents the authentication status of a discovered MCP server.
type AuthStatus string

const (
	AuthProtected   AuthStatus = "protected"
	AuthUnprotected AuthStatus = "unprotected"
	AuthUnknown     AuthStatus = "unknown"
)

// AuthConfidence represents confidence in the auth status determination.
type AuthConfidence string

const (
	AuthConfidenceHigh   AuthConfidence = "high"
	AuthConfidenceMedium AuthConfidence = "medium"
	AuthConfidenceLow    AuthConfidence = "low"
)

// RiskLevel represents the security risk level of a discovered server.
type RiskLevel string

const (
	RiskHigh   RiskLevel = "HIGH"
	RiskMedium RiskLevel = "MEDIUM"
	RiskLow    RiskLevel = "LOW"
)

// TransportType represents the communication transport mechanism of an MCP server.
type TransportType string

const (
	TransportHTTP  TransportType = "http"
	TransportStdio TransportType = "stdio"
)

// ScanConfig holds runtime scan parameters configured via CLI flags.
type ScanConfig struct {
	Target       string        `json:"target"`
	LocalOnly    bool          `json:"local_only"`
	Ports        string        `json:"ports"`
	Timeout      time.Duration `json:"timeout"`
	Concurrency  int           `json:"concurrency"`
	RateLimit    int           `json:"rate_limit"`
	OutputPath   string        `json:"output_path"`
	AllowPublic  bool          `json:"allow_public"`
	Format       string        `json:"format"`
	IncludeStdio bool          `json:"include_stdio"`
}

// ScanRecord represents a single scan invocation stored in SQLite.
type ScanRecord struct {
	ID                int64     `json:"id"`
	StartedAt         time.Time `json:"started_at"`
	EndedAt           time.Time `json:"ended_at"`
	TargetRange       string    `json:"target_range"`
	TotalHostsScanned int       `json:"total_hosts_scanned"`
	ToolVersion       string    `json:"tool_version"`
}

// DiscoveredServer represents an identified HTTP service on an IP and port.
type DiscoveredServer struct {
	ID              int64          `json:"id"`
	ScanID          int64          `json:"scan_id"`
	IP              string         `json:"ip"`
	Port            int            `json:"port"`
	Transport       TransportType  `json:"transport"`
	MCPConfidence   MCPConfidence  `json:"mcp_confidence"`
	ProtocolVersion string         `json:"protocol_version"`
	AuthStatus      AuthStatus     `json:"auth_status"`
	AuthConfidence  AuthConfidence `json:"auth_confidence"`
	RiskLevel       RiskLevel      `json:"risk_level"`
	DetectedAt      time.Time      `json:"detected_at"`
}

// StdioDiscoveredServer represents an MCP server configured over stdio transport in a local AI tool config file.
type StdioDiscoveredServer struct {
	ID                int64         `json:"id"`
	ScanID            int64         `json:"scan_id"`
	SourceTool        string        `json:"source_tool"`
	ConfigFile        string        `json:"config_file"`
	ServerName        string        `json:"server_name"`
	Command           string        `json:"command"`
	ArgsSummary       string        `json:"args_summary"`
	HasEnvBlock       bool          `json:"has_env_block"`
	MCPConfidence     MCPConfidence `json:"mcp_confidence"`
	ProcessMatchFound bool          `json:"process_match_found"`
	MatchedPID        int           `json:"matched_pid,omitempty"`
	DetectedAt        time.Time     `json:"detected_at"`
}

// OpenPort represents a host IP and port that responded to TCP connect scan.
type OpenPort struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// SummaryCounts holds calculated counts across all MCP confidence categories, security risk tiers, and stdio transport findings.
type SummaryCounts struct {
	Confirmed           int
	Likely              int
	Unverifiable        int
	None                int
	Evaluated           int
	Unprotected         int
	Protected           int
	ProtectedLowRisk    int
	ProtectedMediumRisk int
	Unknown             int
	HighRisk            int
	MediumRisk          int
	LowRisk             int
	// Stdio Transport metrics
	StdioConfirmed int
	StdioLikely    int
	StdioTotal     int
}

// CalculateSummaryCounts evaluates slices of DiscoveredServer and StdioDiscoveredServer records and returns aggregated SummaryCounts.
func CalculateSummaryCounts(servers []DiscoveredServer) SummaryCounts {
	var c SummaryCounts

	for _, s := range servers {
		switch s.MCPConfidence {
		case ConfidenceConfirmed:
			c.Confirmed++
		case ConfidenceLikely:
			c.Likely++
		case ConfidenceUnverifiableProtected:
			c.Unverifiable++
		default:
			c.None++
		}

		if s.MCPConfidence == ConfidenceNone {
			continue
		}
		c.Evaluated++

		switch s.AuthStatus {
		case AuthUnprotected:
			c.Unprotected++
		case AuthProtected:
			c.Protected++
			if s.RiskLevel == RiskLow {
				c.ProtectedLowRisk++
			} else if s.RiskLevel == RiskMedium {
				c.ProtectedMediumRisk++
			}
		default:
			c.Unknown++
		}

		switch s.RiskLevel {
		case RiskHigh:
			c.HighRisk++
		case RiskMedium:
			c.MediumRisk++
		case RiskLow:
			c.LowRisk++
		}
	}

	return c
}

// CalculateStdioCounts aggregates counts for stdio-transport discovered servers.
func CalculateStdioCounts(stdioServers []StdioDiscoveredServer) (confirmed int, likely int, total int) {
	for _, s := range stdioServers {
		total++
		switch s.MCPConfidence {
		case ConfidenceConfirmed:
			confirmed++
		case ConfidenceLikely:
			likely++
		}
	}
	return confirmed, likely, total
}


