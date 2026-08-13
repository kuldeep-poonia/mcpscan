package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"mcpscan/internal/auth"
	"mcpscan/internal/detector"
	"mcpscan/internal/report"
	"mcpscan/internal/scanner"
	"mcpscan/internal/storage"
	"mcpscan/pkg/types"
)

const Version = "v1.0.0-dev"

func main() {
	var (
		target      = flag.String("target", "", "Target CIDR network range (e.g. 192.168.1.0/24)")
		local       = flag.Bool("local", false, "Scan local machine loopback only (127.0.0.1)")
		ports       = flag.String("ports", "8000-9000,3000,5000,8080", "Port range or comma-separated list to scan")
		timeout     = flag.Duration("timeout", 2*time.Second, "Per-connection timeout")
		concurrency = flag.Int("concurrency", 100, "Maximum worker pool concurrency")
		rateLimit   = flag.Int("rate-limit", 500, "Maximum requests per second limit")
		output      = flag.String("output", "mcpscan.db", "SQLite database output path")
		format      = flag.String("format", "table", "Output report format (table|json)")
		allowPublic = flag.Bool("i-understand-the-risk", false, "Allow scanning public non-RFC1918 ranges")
		versionFlag = flag.Bool("version", false, "Print MCPScan version and exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "MCPScan %s — Local-only Shadow MCP Server Discovery & Auth Audit Tool\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  mcpscan scan [flags]\n")
		fmt.Fprintf(os.Stderr, "  mcpscan report --db <path.db> [--format table|json]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("MCPScan %s\n", Version)
		os.Exit(0)
	}

	cfg := types.ScanConfig{
		Target:      *target,
		LocalOnly:   *local,
		Ports:       *ports,
		Timeout:     *timeout,
		Concurrency: *concurrency,
		RateLimit:   *rateLimit,
		OutputPath:  *output,
		AllowPublic: *allowPublic,
		Format:      *format,
	}

	// Instantiate pipeline stubs
	_ = scanner.NewScanner(cfg)
	_ = detector.NewDetector(cfg.Timeout)
	_ = auth.NewChecker(cfg.Timeout)
	_ = storage.NewStorage(cfg.OutputPath)
	rep := report.NewReporter(cfg.Format)

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	// For skeleton Phase 0, render initial notice & exiting cleanly
	_ = rep.Render(os.Stdout, &types.ScanRecord{ToolVersion: Version}, nil)
}
