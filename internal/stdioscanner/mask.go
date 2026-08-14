package stdioscanner

import (
	"math"
	"regexp"
	"strings"
)

// List of credential-indicating substrings used for key-name heuristic masking.
var sensitiveKeyTerms = []string{
	"key",
	"token",
	"secret",
	"password",
	"passwd",
	"auth",
	"credential",
	"bearer",
	"apikey",
	"api_key",
	"access_token",
	"private_key",
}

// Regex to identify key=value or --flag=value patterns in CLI arguments or command strings.
var keyValueArgRegex = regexp.MustCompile(`(?i)^(--?[\w\.\-]+|[\w\.\-]+)=(.+)$`)

// MaskValue applies partial masking to a sensitive value string.
// If length > 8: preserves first 3 and last 3 characters (e.g. "sk-...a1b").
// If length <= 8: returns "******".
func MaskValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) <= 8 {
		return "******"
	}
	return val[:3] + "..." + val[len(val)-3:]
}

// isSensitiveKey checks if a flag or environment key name contains sensitive terms.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, term := range sensitiveKeyTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

// calculateShannonEntropy measures the randomness of a string to detect high-entropy tokens.
func calculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Recognized executable, script, and configuration file extensions in developer tooling.
var recognizedPathExtensions = []string{
	".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".json", ".exe",
	".sh", ".bat", ".cmd", ".ps1", ".rb", ".go", ".bin", ".conf", ".yaml",
	".yml", ".toml", ".node", ".dll", ".so", ".dylib",
}

// Recognized standard directory root prefixes across Windows, macOS, and Linux.
var recognizedPathPrefixes = []string{
	"/usr/", "/etc/", "/home/", "/opt/", "/var/", "/root/", "/bin/", "/lib/",
	"~/", "./", "../", "c:\\", "d:\\", "e:\\", "c:/", "d:/", "e:/",
}

// isLikelyFilesystemPath distinguishes genuine filesystem paths from slash-containing base64 secrets.
func isLikelyFilesystemPath(s string) bool {
	if !strings.ContainsAny(s, `/\`) {
		return false
	}

	lower := strings.ToLower(s)

	// Check 1: Known absolute or relative root path prefix
	for _, prefix := range recognizedPathPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	// Windows drive letter check (e.g. F:\, Z:/)
	if len(lower) >= 3 && lower[1] == ':' && (lower[2] == '\\' || lower[2] == '/') {
		return true
	}

	// Check 2: Recognized file extension at the end of the path
	for _, ext := range recognizedPathExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	// Check 3: Scoped package identifier (e.g. @modelcontextprotocol/server-filesystem)
	if strings.HasPrefix(lower, "@") && strings.Count(lower, "/") == 1 && !strings.Contains(lower, "\\") {
		return true
	}

	return false
}

// isHighEntropyToken evaluates whether a standalone string appears to be an API key/token.
func isHighEntropyToken(s string) bool {
	// Must be contiguous with no whitespace, length >= 16
	if len(s) < 16 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}

	lower := strings.ToLower(s)

	// Common credential prefix patterns (e.g. sk-, ghp_, gho_, xoxb-, ey...)
	if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "ghp_") ||
		strings.HasPrefix(lower, "gho_") || strings.HasPrefix(lower, "xox") ||
		strings.HasPrefix(lower, "eyj") {
		return true
	}

	// Genuine structured filesystem paths are exempted from standalone token masking
	if isLikelyFilesystemPath(s) {
		return false
	}

	// Shannon entropy threshold for generic high-entropy strings (including base64/hex hashes and AWS secrets)
	return calculateShannonEntropy(s) > 3.2
}

// MaskString sanitizes a single command or argument token using two-layer masking heuristics.
func MaskString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Layer 1: Key=Value or --Flag=Value heuristic
	if matches := keyValueArgRegex.FindStringSubmatch(s); len(matches) == 3 {
		key := matches[1]
		val := matches[2]
		if isSensitiveKey(key) || isHighEntropyToken(val) {
			return key + "=" + MaskValue(val)
		}
		return s
	}

	// Layer 2: Standalone value-shape heuristic
	if isHighEntropyToken(s) {
		return MaskValue(s)
	}

	return s
}

// MaskArgs applies two-layer masking to each argument in a slice of CLI arguments.
func MaskArgs(args []string) []string {
	if args == nil {
		return nil
	}
	masked := make([]string, len(args))
	for i, arg := range args {
		// Handle potential split flags (e.g. "--api-key", "sk-1234567890abcdef")
		if i > 0 && isSensitiveKey(args[i-1]) && !strings.HasPrefix(arg, "-") {
			masked[i] = MaskValue(arg)
		} else {
			masked[i] = MaskString(arg)
		}
	}
	return masked
}

// SummarizeArgs produces a clean, sanitized single-line summary of command arguments.
func SummarizeArgs(args []string) string {
	masked := MaskArgs(args)
	if len(masked) == 0 {
		return ""
	}
	return strings.Join(masked, " ")
}
