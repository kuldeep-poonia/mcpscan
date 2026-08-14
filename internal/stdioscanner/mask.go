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

// isHighEntropyToken evaluates whether a standalone string appears to be an API key/token.
func isHighEntropyToken(s string) bool {
	// Must be contiguous with no whitespace, length >= 16
	if len(s) < 16 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}

	// Common prefix patterns (e.g. sk-, ghp_, gho_, xoxb-, ey...)
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "ghp_") ||
		strings.HasPrefix(lower, "gho_") || strings.HasPrefix(lower, "xox") ||
		strings.HasPrefix(lower, "eyj") {
		return true
	}

	// Shannon entropy threshold for generic high-entropy strings (e.g. hex/base64 hashes)
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
