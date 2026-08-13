package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"mcpscan/pkg/types"
)

// TestResolveTargets_CIDRExpansion verifies 100% correctness of CIDR expansion to IP list.
func TestResolveTargets_CIDRExpansion(t *testing.T) {
	cfg := types.ScanConfig{Target: "192.168.1.0/29"}
	s := NewScanner(cfg)

	targets, err := s.ResolveTargets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error expanding CIDR: %v", err)
	}

	expectedIPs := []string{
		"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3",
		"192.168.1.4", "192.168.1.5", "192.168.1.6", "192.168.1.7",
	}

	if len(targets) != len(expectedIPs) {
		t.Fatalf("expected %d IPs, got %d", len(expectedIPs), len(targets))
	}

	for i, expected := range expectedIPs {
		if targets[i] != expected {
			t.Errorf("at index %d: expected %s, got %s", i, expected, targets[i])
		}
	}
}

// TestResolveTargets_HostCountCap verifies 100% enforcement of the 1024 host limit.
func TestResolveTargets_HostCountCap(t *testing.T) {
	// /21 CIDR contains 2048 hosts (>1024 cap)
	cfg := types.ScanConfig{Target: "192.168.0.0/21"}
	s := NewScanner(cfg)

	_, err := s.ResolveTargets(context.Background())
	if err == nil {
		t.Fatal("expected error for CIDR exceeding 1024 hosts, got nil")
	}

	if !errors.Is(err, ErrTargetRangeExceeded) {
		t.Errorf("expected ErrTargetRangeExceeded, got: %v", err)
	}
}

// TestResolveTargets_RFC1918Validation verifies security check for public vs private IPs.
func TestResolveTargets_RFC1918Validation(t *testing.T) {
	// Public IP without --i-understand-the-risk flag must fail
	cfgPublic := types.ScanConfig{Target: "8.8.8.8", AllowPublic: false}
	sPublic := NewScanner(cfgPublic)
	_, err := sPublic.ResolveTargets(context.Background())
	if err == nil || !errors.Is(err, ErrPublicTargetDenied) {
		t.Errorf("expected ErrPublicTargetDenied for public IP 8.8.8.8, got: %v", err)
	}

	// Public IP with --i-understand-the-risk flag must succeed
	cfgPublicAllowed := types.ScanConfig{Target: "8.8.8.8", AllowPublic: true}
	sPublicAllowed := NewScanner(cfgPublicAllowed)
	targets, err := sPublicAllowed.ResolveTargets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error when AllowPublic is true: %v", err)
	}
	if len(targets) != 1 || targets[0] != "8.8.8.8" {
		t.Errorf("expected [8.8.8.8], got %v", targets)
	}

	// Private IP (10.0.0.1) without flag must succeed
	cfgPrivate := types.ScanConfig{Target: "10.0.0.1", AllowPublic: false}
	sPrivate := NewScanner(cfgPrivate)
	targetsPriv, err := sPrivate.ResolveTargets(context.Background())
	if err != nil {
		t.Fatalf("unexpected error for private IP: %v", err)
	}
	if len(targetsPriv) != 1 || targetsPriv[0] != "10.0.0.1" {
		t.Errorf("expected [10.0.0.1], got %v", targetsPriv)
	}
}

// TestParsePorts verifies range parsing, deduplication, and boundary checking.
func TestParsePorts(t *testing.T) {
	validInput := "8000-8003, 3000, 5000, 8002"
	ports, err := ParsePorts(validInput)
	if err != nil {
		t.Fatalf("unexpected error parsing valid ports: %v", err)
	}

	expected := []int{3000, 5000, 8000, 8001, 8002, 8003}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, exp := range expected {
		if ports[i] != exp {
			t.Errorf("at index %d: expected port %d, got %d", i, exp, ports[i])
		}
	}

	invalidInputs := []string{
		"abc",
		"8000-7000",
		"0",
		"70000",
	}

	for _, inv := range invalidInputs {
		_, err := ParsePorts(inv)
		if err == nil {
			t.Errorf("expected error for invalid port input %q, got nil", inv)
		}
	}
}

// TestScanPorts_OpenPortAccuracy verifies open port detection accuracy (>= 99% threshold).
func TestScanPorts_OpenPortAccuracy(t *testing.T) {
	// Start 3 local TCP test listeners
	var listeners []net.Listener
	var openPorts []int

	for i := 0; i < 3; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to open test listener: %v", err)
		}
		defer l.Close()
		listeners = append(listeners, l)

		_, portStr, _ := net.SplitHostPort(l.Addr().String())
		p, _ := strconv.Atoi(portStr)
		openPorts = append(openPorts, p)
	}

	cfg := types.ScanConfig{
		Concurrency: 10,
		Timeout:     500 * time.Millisecond,
		RateLimit:   500,
	}
	s := NewScanner(cfg)

	detected, err := s.ScanPorts(context.Background(), []string{"127.0.0.1"}, openPorts)
	if err != nil {
		t.Fatalf("unexpected error scanning open ports: %v", err)
	}

	if len(detected) != len(openPorts) {
		t.Fatalf("expected %d open ports detected, got %d", len(openPorts), len(detected))
	}

	accuracy := (float64(len(detected)) / float64(len(openPorts))) * 100.0
	if accuracy < 99.0 {
		t.Errorf("open port detection accuracy %.2f%% below 99.0%% threshold", accuracy)
	}
}

// TestClosedPortFalsePositiveRate verifies closed-port false positive rate <= 0.5%.
func TestClosedPortFalsePositiveRate(t *testing.T) {
	// Generate a range of 100 unlikely open high ports on localhost
	var closedPorts []int
	for p := 59100; p < 59200; p++ {
		closedPorts = append(closedPorts, p)
	}

	cfg := types.ScanConfig{
		Concurrency: 50,
		Timeout:     50 * time.Millisecond,
		RateLimit:   1000,
	}
	s := NewScanner(cfg)

	detected, err := s.ScanPorts(context.Background(), []string{"127.0.0.1"}, closedPorts)
	if err != nil {
		t.Fatalf("unexpected error scanning closed ports: %v", err)
	}

	falsePositives := len(detected)
	falsePositiveRate := (float64(falsePositives) / float64(len(closedPorts))) * 100.0

	t.Logf("Scanned %d closed ports: %d false positives (Rate: %.2f%%)", len(closedPorts), falsePositives, falsePositiveRate)

	if falsePositiveRate > 0.5 {
		t.Errorf("closed port false positive rate %.2f%% exceeds 0.5%% threshold", falsePositiveRate)
	}
}

// TestTimeoutHandling verifies that an unreachable target scan does not block beyond (configured timeout + 100ms).
func TestTimeoutHandling(t *testing.T) {
	configuredTimeout := 300 * time.Millisecond
	cfg := types.ScanConfig{
		Concurrency: 10,
		Timeout:     configuredTimeout,
		RateLimit:   500,
	}
	s := NewScanner(cfg)

	// Target 192.0.2.1 (RFC 5737 TEST-NET-1 unroutable IP)
	unreachableTarget := "192.0.2.1"
	testPort := 81

	start := time.Now()
	_, err := s.ScanPorts(context.Background(), []string{unreachableTarget}, []int{testPort})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error scanning unreachable host: %v", err)
	}

	maxAllowedTime := configuredTimeout + 100*time.Millisecond
	t.Logf("Configured timeout: %v, Actual elapsed time: %v, Max allowed: %v", configuredTimeout, elapsed, maxAllowedTime)

	if elapsed > maxAllowedTime {
		t.Errorf("elapsed time %v exceeded max allowed tolerance %v", elapsed, maxAllowedTime)
	}
}
