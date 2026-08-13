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

// DiscoveredServer represents an identified service on an IP and port.
type DiscoveredServer struct {
	ID              int64         `json:"id"`
	ScanID          int64         `json:"scan_id"`
	IP              string        `json:"ip"`
	Port            int           `json:"port"`
	MCPConfidence   MCPConfidence `json:"mcp_confidence"`
	ProtocolVersion string        `json:"protocol_version"`
	AuthStatus      AuthStatus    `json:"auth_status"`
	AuthConfidence  AuthConfidence`json:"auth_confidence"`
	RiskLevel       RiskLevel     `json:"risk_level"`
	DetectedAt      time.Time     `json:"detected_at"`
}

// OpenPort represents a host IP and port that responded to TCP connect scan.
type OpenPort struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// SummaryCounts holds calculated counts across all 4 MCP confidence categories and security risk tiers.
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
}

// CalculateSummaryCounts evaluates a slice of DiscoveredServer records and returns an aggregated SummaryCounts struct.
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

