package stdioscanner

import (
	"strings"
	"testing"
)

// TestMaskValue verifies partial masking format and boundary handling.
func TestMaskValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "******"},
		{"12345678", "******"},
		{"123456789", "123...789"},
		{"sk-ant-api03-abcdef123456789", "sk-...789"},
	}

	for _, tc := range tests {
		got := MaskValue(tc.input)
		if got != tc.expected {
			t.Errorf("MaskValue(%q) = %q, expected %q", tc.input, got, tc.expected)
		}
	}
}

// TestMaskString_KeyHeuristics verifies key/flag-based credential masking.
func TestMaskString_KeyHeuristics(t *testing.T) {
	tests := []struct {
		input       string
		shouldMask  bool
		expectedSub string
	}{
		{"--api-key=sk-ant-api03-abcdef123456789", true, "--api-key=sk-...789"},
		{"--token=ghp_1234567890abcdef123456789", true, "--token=ghp...789"},
		{"-password=supersecretpassword123", true, "-password=sup...123"},
		{"SECRET_KEY=customsecrettokenvalue999", true, "SECRET_KEY=cus...999"},
		{"--port=8080", false, "--port=8080"},
		{"--verbose", false, "--verbose"},
		{"run_server.py", false, "run_server.py"},
	}

	for _, tc := range tests {
		got := MaskString(tc.input)
		if tc.shouldMask {
			if got == tc.input {
				t.Errorf("MaskString(%q) failed to mask sensitive token", tc.input)
			}
			if got != tc.expectedSub {
				t.Errorf("MaskString(%q) = %q, expected %q", tc.input, got, tc.expectedSub)
			}
		} else {
			if got != tc.input {
				t.Errorf("MaskString(%q) unexpectedly masked non-sensitive string to %q", tc.input, got)
			}
		}
	}
}

// TestMaskString_ValueShapeHeuristics verifies standalone high-entropy token masking.
func TestMaskString_ValueShapeHeuristics(t *testing.T) {
	highEntropyToken := "a8f9c7e2b1d4f6a8e0c2b4d6f8a0e2c4" // 32-char hex token
	got := MaskString(highEntropyToken)

	if got == highEntropyToken {
		t.Errorf("MaskString failed to detect high entropy token %q", highEntropyToken)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("expected masked format with ellipsis, got %q", got)
	}
}

// TestMaskArgs_SplitFlags verifies split CLI arguments (flag followed by value).
func TestMaskArgs_SplitFlags(t *testing.T) {
	args := []string{
		"python",
		"server.py",
		"--api-key",
		"sk-ant-api03-abcdef123456789",
		"--port",
		"8080",
	}

	masked := MaskArgs(args)
	summary := SummarizeArgs(args)

	if masked[3] == "sk-ant-api03-abcdef123456789" {
		t.Errorf("MaskArgs failed to mask split argument value")
	}
	if strings.Contains(summary, "abcdef123456") {
		t.Errorf("SummarizeArgs leaked raw secret in summary: %s", summary)
	}
	if !strings.Contains(summary, "python server.py --api-key sk-...789 --port 8080") {
		t.Errorf("unexpected summary output: %s", summary)
	}
}

// TestMaskString_LongPathsNotMasked asserts that long filesystem paths are NOT falsely masked by entropy heuristics.
func TestMaskString_LongPathsNotMasked(t *testing.T) {
	longPaths := []string{
		`C:\Users\kuldeep\Desktop\projects\mcp-server\build\output\server.js`,
		`/usr/local/lib/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`,
		`D:\Development\ai-tools\antigravity\mcp_servers\database_connector_v2.py`,
		`C:\Program Files\nodejs\node_modules\npm\bin\npx-cli.js`,
		`--config=/etc/mcp/configs/production_server_v1_settings.json`,
	}

	for _, path := range longPaths {
		got := MaskString(path)
		if got != path {
			t.Errorf("MaskString falsely masked structured filesystem path %q to %q", path, got)
		}
	}
}

// TestMaskString_SlashContainingSecretsMasked asserts that high-entropy secrets containing slashes
// (e.g. AWS Secret Access Keys or base64 tokens) are correctly MASKED and do not bypass detection.
func TestMaskString_SlashContainingSecretsMasked(t *testing.T) {
	slashSecrets := []struct {
		input       string
		expectedSub string
	}{
		// Real-world AWS Secret Access Key shape with slashes
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJa...KEY"},
		// Base64 encoded token with slashes and plus signs
		{"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "AQI...yA="},
		// Inline CLI argument with slash-containing secret
		{"--aws-secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "--aws-secret=wJa...KEY"},
	}

	for _, tc := range slashSecrets {
		got := MaskString(tc.input)
		if got == tc.input {
			t.Errorf("SECURITY REGRESSION: MaskString failed to mask slash-containing secret: %q", tc.input)
		}
		if got != tc.expectedSub {
			t.Errorf("MaskString(%q) = %q, expected %q", tc.input, got, tc.expectedSub)
		}
	}
}


