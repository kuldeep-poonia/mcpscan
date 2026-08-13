package report

import (
	"bytes"
	"strings"
	"testing"

	"mcpscan/pkg/types"
)

func TestRender(t *testing.T) {
	rep := NewReporter("table")
	var buf bytes.Buffer
	err := rep.Render(&buf, &types.ScanRecord{}, nil)
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Stdio Transport Blind Spot") {
		t.Errorf("expected report output to contain limitation notice, got: %s", out)
	}
}
