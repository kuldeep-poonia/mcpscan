// Package scanner provides target resolution and TCP connect port scanning logic.
package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mcpscan/pkg/types"
)

const DefaultMaxHostCap = 1024

var (
	// ErrTargetRangeExceeded is returned when the target host count exceeds the allowed limit.
	ErrTargetRangeExceeded = errors.New("target range exceeds maximum allowed host cap (1024 hosts)")
	// ErrPublicTargetDenied is returned when a public non-RFC1918 target is specified without explicit risk acceptance.
	ErrPublicTargetDenied = errors.New("scanning public IP range is denied without --i-understand-the-risk flag")
	// ErrInvalidTarget is returned when a target cannot be parsed as a valid IP or CIDR.
	ErrInvalidTarget = errors.New("invalid target specification or CIDR format")
	// ErrInvalidPortRange is returned when a port string cannot be parsed into valid 1-65535 ports.
	ErrInvalidPortRange = errors.New("invalid port specification")
)

// Scanner performs target resolution and TCP connect scanning.
type Scanner struct {
	config types.ScanConfig
	maxCap int
}

// NewScanner constructs a Scanner instance with the given configuration.
func NewScanner(cfg types.ScanConfig) *Scanner {
	return &Scanner{
		config: cfg,
		maxCap: DefaultMaxHostCap,
	}
}

// ResolveTargets expands CIDRs/IPs into a bounded slice of IP address strings.
func (s *Scanner) ResolveTargets(ctx context.Context) ([]string, error) {
	if s.config.LocalOnly || strings.TrimSpace(s.config.Target) == "" {
		return []string{"127.0.0.1"}, nil
	}

	rawTargets := strings.Split(s.config.Target, ",")
	var resolved []string
	seen := make(map[string]bool)

	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		ips, err := s.expandTargetItem(raw)
		if err != nil {
			return nil, err
		}

		for _, ipStr := range ips {
			if !seen[ipStr] {
				seen[ipStr] = true
				resolved = append(resolved, ipStr)
			}
		}

		if len(resolved) > s.maxCap {
			return nil, fmt.Errorf("%w: total resolved hosts (%d) exceeds limit (%d)", ErrTargetRangeExceeded, len(resolved), s.maxCap)
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidTarget, s.config.Target)
	}

	return resolved, nil
}

// expandTargetItem parses a single target (IP or CIDR) into individual IP strings.
func (s *Scanner) expandTargetItem(item string) ([]string, error) {
	// Check if it's a CIDR notation
	if strings.Contains(item, "/") {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid CIDR %q", ErrInvalidTarget, item)
		}

		ips, err := s.expandCIDR(ipNet)
		if err != nil {
			return nil, err
		}

		for _, ipStr := range ips {
			if err := s.validateIPSecurity(net.ParseIP(ipStr)); err != nil {
				return nil, err
			}
		}

		return ips, nil
	}

	// Single IP address
	parsedIP := net.ParseIP(item)
	if parsedIP == nil {
		return nil, fmt.Errorf("%w: invalid IP %q", ErrInvalidTarget, item)
	}

	if err := s.validateIPSecurity(parsedIP); err != nil {
		return nil, err
	}

	return []string{parsedIP.String()}, nil
}

// expandCIDR calculates all host IPs within an IPNet block.
func (s *Scanner) expandCIDR(ipNet *net.IPNet) ([]string, error) {
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		// For IPv6 CIDRs, handle loopback/single host or cap
		ones, bits := ipNet.Mask.Size()
		if bits-ones > 10 { // > 1024 hosts
			return nil, fmt.Errorf("%w: IPv6 block /%d exceeds max cap", ErrTargetRangeExceeded, ones)
		}
		var ips []string
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			ips = append(ips, ip.String())
			if len(ips) > s.maxCap {
				return nil, fmt.Errorf("%w: CIDR host count exceeds %d", ErrTargetRangeExceeded, s.maxCap)
			}
		}
		return ips, nil
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ip4) & mask
	end := start | ^mask

	totalHostCount := uint64(end - start + 1)
	if totalHostCount > uint64(s.maxCap) {
		return nil, fmt.Errorf("%w: CIDR host count (%d) exceeds max limit (%d)", ErrTargetRangeExceeded, totalHostCount, s.maxCap)
	}

	var ips []string
	for i := start; i <= end; i++ {
		ipBuf := make(net.IP, 4)
		binary.BigEndian.PutUint32(ipBuf, i)
		ips = append(ips, ipBuf.String())
	}

	return ips, nil
}

// incrementIP adds 1 to an IP address byte slice.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// validateIPSecurity enforces that targets are RFC1918 or loopback unless AllowPublic is explicitly true.
func (s *Scanner) validateIPSecurity(ip net.IP) error {
	if s.config.AllowPublic {
		return nil
	}

	if isPrivateOrLoopbackIP(ip) {
		return nil
	}

	return fmt.Errorf("%w: IP %s is not a private RFC1918 or loopback address", ErrPublicTargetDenied, ip.String())
}

// isPrivateOrLoopbackIP returns true if ip is loopback, private (RFC1918 / RFC4193), or link-local.
func isPrivateOrLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// ParsePorts converts a port range specification string (e.g. "8000-8005,3000,5000") into a sorted slice of unique ints.
func ParsePorts(portsStr string) ([]int, error) {
	portsStr = strings.TrimSpace(portsStr)
	if portsStr == "" {
		return nil, fmt.Errorf("%w: empty port specification", ErrInvalidPortRange)
	}

	portMap := make(map[int]bool)
	chunks := strings.Split(portsStr, ",")

	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		if strings.Contains(chunk, "-") {
			parts := strings.Split(chunk, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("%w: invalid range format %q", ErrInvalidPortRange, chunk)
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("%w: invalid port range %q", ErrInvalidPortRange, chunk)
			}

			for p := start; p <= end; p++ {
				portMap[p] = true
			}
		} else {
			p, err := strconv.Atoi(chunk)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("%w: invalid port number %q", ErrInvalidPortRange, chunk)
			}
			portMap[p] = true
		}
	}

	if len(portMap) == 0 {
		return nil, fmt.Errorf("%w: no valid ports parsed", ErrInvalidPortRange)
	}

	ports := make([]int, 0, len(portMap))
	for p := range portMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	return ports, nil
}

// ScanPorts executes a TCP connect scan against the resolved targets using a worker pool and a single shared rate limiter.
func (s *Scanner) ScanPorts(ctx context.Context, targets []string, ports []int) ([]types.OpenPort, error) {
	if len(targets) == 0 || len(ports) == 0 {
		return []types.OpenPort{}, nil
	}

	concurrency := s.config.Concurrency
	if concurrency <= 0 {
		concurrency = 100
	}

	rateLimit := s.config.RateLimit
	if rateLimit <= 0 {
		rateLimit = 500
	}

	// Single shared rate limiter across the entire worker pool
	interval := time.Second / time.Duration(rateLimit)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Bounded worker pool channel
	sem := make(chan struct{}, concurrency)

	var (
		mu        sync.Mutex
		openPorts []types.OpenPort
		wg        sync.WaitGroup
	)

	for _, target := range targets {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				return openPorts, ctx.Err()
			case sem <- struct{}{}:
			}

			// Consume token from single shared rate limiter
			select {
			case <-ctx.Done():
				<-sem
				wg.Wait()
				return openPorts, ctx.Err()
			case <-ticker.C:
			}

			wg.Add(1)
			go func(ip string, p int) {
				defer func() {
					<-sem
					wg.Done()
				}()

				addr := net.JoinHostPort(ip, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
				if err == nil {
					conn.Close()
					mu.Lock()
					openPorts = append(openPorts, types.OpenPort{IP: ip, Port: p})
					mu.Unlock()
				}
			}(target, port)
		}
	}

	wg.Wait()

	// Sort results for deterministic output
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].IP == openPorts[j].IP {
			return openPorts[i].Port < openPorts[j].Port
		}
		return openPorts[i].IP < openPorts[j].IP
	})

	return openPorts, nil
}
