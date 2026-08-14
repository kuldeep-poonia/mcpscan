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
