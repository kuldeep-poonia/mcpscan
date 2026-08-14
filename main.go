package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"mcpscan/internal/auth"
	"mcpscan/internal/detector"
	"mcpscan/internal/report"
	"mcpscan/internal/scanner"
	"mcpscan/internal/stdioscanner"
	"mcpscan/internal/storage"
	"mcpscan/pkg/types"
	"runtime"
)

const Version = "v1.1.0"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "report" {
		runReportSubcommand(os.Args[2:])
		return
	}

	// Default / scan subcommand flags
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	target := scanCmd.String("target", "", "Target CIDR network range (e.g. 192.168.1.0/24)")
	local := scanCmd.Bool("local", false, "Scan local machine loopback only (127.0.0.1)")
	ports := scanCmd.String("ports", "8000-9000,3000,5000,8080", "Port range or comma-separated list to scan")
	timeout := scanCmd.Duration("timeout", 2*time.Second, "Per-connection timeout")
	concurrency := scanCmd.Int("concurrency", 100, "Maximum worker pool concurrency")
	rateLimit := scanCmd.Int("rate-limit", 500, "Maximum requests per second limit")
	output := scanCmd.String("output", "mcpscan.db", "SQLite database output path")
	format := scanCmd.String("format", "table", "Output report format (table|json)")
	includeStdio := scanCmd.Bool("include-stdio", false, "Discover local stdio-transport MCP servers from AI tool configs")
	allowPublic := scanCmd.Bool("i-understand-the-risk", false, "Allow scanning public non-RFC1918 ranges")
	versionFlag := scanCmd.Bool("version", false, "Print MCPScan version and exit")

	scanCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "MCPScan %s — Local-only Shadow MCP Server Discovery & Auth Audit Tool\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  mcpscan scan [flags]\n")
		fmt.Fprintf(os.Stderr, "  mcpscan report --db <path.db> [--format table|json]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		scanCmd.PrintDefaults()
	}

	argsToParse := os.Args[1:]
	if len(os.Args) > 1 && os.Args[1] == "scan" {
		argsToParse = os.Args[2:]
	}

	if err := scanCmd.Parse(argsToParse); err != nil {
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Printf("MCPScan %s\n", Version)
		os.Exit(0)
	}

	if len(os.Args) == 1 {
		scanCmd.Usage()
		os.Exit(0)
	}

	cfg := types.ScanConfig{
		Target:       *target,
		LocalOnly:    *local,
		Ports:        *ports,
		Timeout:      *timeout,
		Concurrency:  *concurrency,
		RateLimit:    *rateLimit,
		OutputPath:   *output,
		IncludeStdio: *includeStdio,
		AllowPublic:  *allowPublic,
		Format:       *format,
	}

	ctx := context.Background()

	// 1. Target Resolution
	sc := scanner.NewScanner(cfg)
	targets, err := sc.ResolveTargets(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Target resolution error: %v\n", err)
		os.Exit(1)
	}

	parsedPorts, err := scanner.ParsePorts(cfg.Ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Port specification error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Target Resolver: Resolved %d target host(s)\n", len(targets))

	// 2. TCP Port Scanning (Phase 1)
	startScan := time.Now()
	openPorts, err := sc.ScanPorts(ctx, targets, parsedPorts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Port scan error: %v\n", err)
		os.Exit(1)
	}
	scanDuration := time.Since(startScan)

	fmt.Printf("[+] Port Scanner: Discovered %d open TCP port(s) across %d target host(s) in %v\n", len(openPorts), len(targets), scanDuration)

	// 3. MCP Protocol Detection (Phase 2 - 3-Layer Verification)
	det := detector.NewDetector(cfg.Timeout)
	discovered, _ := det.DetectBatch(ctx, openPorts)

	detCounts := types.CalculateSummaryCounts(discovered, nil)
	fmt.Printf("[+] MCP Detector: Identified %d confirmed, %d likely, %d unverifiable (protected), and %d non-MCP server(s)\n",
		detCounts.Confirmed, detCounts.Likely, detCounts.Unverifiable, detCounts.None)

	// 4. Auth Checking (Phase 3 - Single Probe Audit)
	chk := auth.NewChecker(cfg.Timeout)
	auditedServers, _ := chk.CheckAuthBatch(ctx, discovered)

	authCounts := types.CalculateSummaryCounts(auditedServers, nil)
	if authCounts.Evaluated > 0 {
		protectedStr := formatProtectedSummary(authCounts.Protected, authCounts.ProtectedLowRisk, authCounts.ProtectedMediumRisk)
		fmt.Printf("[+] Auth Audit: Evaluated %d server(s): %d unprotected (HIGH risk), %s, %d unknown (MEDIUM risk)\n",
			authCounts.Evaluated, authCounts.Unprotected, protectedStr, authCounts.Unknown)
	}

	// 5. Stdio Transport Detection (v2 - Opt-in)
	var stdioDiscovered []types.StdioDiscoveredServer
	if cfg.IncludeStdio {
		stdioDet := stdioscanner.NewDetector(nil)
		stdioDiscovered, err = stdioDet.DetectLocal(ctx, runtime.GOOS, os.Getenv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARNING] Stdio detector error: %v\n", err)
		} else {
			stdioCounts := types.CalculateSummaryCounts(nil, stdioDiscovered)
			fmt.Printf("[+] Stdio Detector: Discovered %d server(s) across local AI tool configs (%d running, %d dormant)\n",
				stdioCounts.StdioTotal, stdioCounts.StdioConfirmed, stdioCounts.StdioLikely)
		}
	}

	// 6. Storage (SQLite Persistence)
	store := storage.NewStorage(cfg.OutputPath)
	if err := store.InitSchema(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Storage schema initialization error: %v\n", err)
		os.Exit(1)
	}

	record := &types.ScanRecord{
		StartedAt:         startScan,
		EndedAt:           time.Now(),
		TargetRange:       cfg.Target,
		TotalHostsScanned: len(targets),
		ToolVersion:       Version,
	}

	if err := store.SaveScan(ctx, record, auditedServers); err != nil {
		fmt.Fprintf(os.Stderr, "Storage write error: %v\n", err)
		os.Exit(1)
	}

	if len(stdioDiscovered) > 0 {
		if err := store.SaveStdioDiscoveredServers(ctx, record.ID, stdioDiscovered); err != nil {
			fmt.Fprintf(os.Stderr, "Storage stdio write error: %v\n", err)
		}
	}

	fmt.Printf("[+] Storage: Persisted scan #%d results to %s\n\n", record.ID, cfg.OutputPath)

	// 7. Reporter (Table / JSON Rendering)
	rep := report.NewReporter(cfg.Format)
	_ = rep.Render(os.Stdout, record, auditedServers, stdioDiscovered)
}

func runReportSubcommand(args []string) {
	reportCmd := flag.NewFlagSet("report", flag.ExitOnError)
	dbPath := reportCmd.String("db", "mcpscan.db", "SQLite database file path")
	format := reportCmd.String("format", "table", "Output format (table|json)")

	if err := reportCmd.Parse(args); err != nil {
		os.Exit(1)
	}

	ctx := context.Background()
	store := storage.NewStorage(*dbPath)
	record, servers, err := store.GetLastScan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading database report from %s: %v\n", *dbPath, err)
		os.Exit(1)
	}

	if record == nil || record.ID == 0 {
		fmt.Fprintf(os.Stderr, "No scan records found in database file %s\n", *dbPath)
		os.Exit(1)
	}

	stdioServers, _ := store.GetStdioDiscoveredServers(ctx, record.ID)

	rep := report.NewReporter(*format)
	_ = rep.Render(os.Stdout, record, servers, stdioServers)
}

func formatProtectedSummary(total, lowRisk, mediumRisk int) string {
	if lowRisk > 0 && mediumRisk > 0 {
		return fmt.Sprintf("%d protected (%d LOW risk, %d MEDIUM risk)", total, lowRisk, mediumRisk)
	}
	if mediumRisk > 0 {
		return fmt.Sprintf("%d protected (MEDIUM risk)", total)
	}
	return fmt.Sprintf("%d protected (LOW risk)", total)
}

