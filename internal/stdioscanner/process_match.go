package stdioscanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// OSProcessInfo represents a running process observed on the local operating system.
type OSProcessInfo struct {
	PID         int    `json:"ProcessId"`
	Name        string `json:"Name"`
	CommandLine string `json:"CommandLine"`
}

// ProcessMatcher defines the interface for cross-referencing stdio server configs against running processes.
type ProcessMatcher interface {
	FindMatch(command string, argsSummary string) (matched bool, pid int)
}

// OSProcessMatcher implements ProcessMatcher using non-elevated OS process listing facilities.
type OSProcessMatcher struct {
	processes []OSProcessInfo
}

// NewOSProcessMatcher initializes a process matcher by snapshotting the current OS process table.
func NewOSProcessMatcher() *OSProcessMatcher {
	matcher := &OSProcessMatcher{}
	procs, err := enumerateOSProcesses()
	if err == nil {
		matcher.processes = procs
	}
	return matcher
}

// NewStaticProcessMatcher creates a process matcher pre-populated with mock processes for unit testing.
func NewStaticProcessMatcher(procs []OSProcessInfo) *OSProcessMatcher {
	return &OSProcessMatcher{
		processes: procs,
	}
}

// enumerateOSProcesses lists running processes across Windows, Linux, and macOS using non-elevated facilities.
func enumerateOSProcesses() ([]OSProcessInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return enumerateWindowsProcesses()
	case "linux":
		return enumerateLinuxProcesses()
	case "darwin":
		return enumerateDarwinProcesses()
	default:
		return nil, fmt.Errorf("unsupported OS for process matching: %s", runtime.GOOS)
	}
}

// enumerateWindowsProcesses enumerates processes on Windows via non-elevated CIM query.
func enumerateWindowsProcesses() ([]OSProcessInfo, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | ConvertTo-Json -Compress")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("windows process enumeration error: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}

	// Handle single process object vs array of processes
	if strings.HasPrefix(trimmed, "{") {
		var single OSProcessInfo
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, err
		}
		return []OSProcessInfo{single}, nil
	}

	var procs []OSProcessInfo
	if err := json.Unmarshal([]byte(trimmed), &procs); err != nil {
		return nil, err
	}
	return procs, nil
}

// enumerateLinuxProcesses reads process information from /proc filesystem.
func enumerateLinuxProcesses() ([]OSProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var procs []OSProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		cmdlineBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue // Process exited or access restricted
		}

		// /proc/[pid]/cmdline separates arguments with null bytes \x00
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "" {
			continue
		}

		commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		name := strings.TrimSpace(string(commBytes))

		procs = append(procs, OSProcessInfo{
			PID:         pid,
			Name:        name,
			CommandLine: cmdline,
		})
	}

	return procs, nil
}

// enumerateDarwinProcesses enumerates processes on macOS using standard ps command.
func enumerateDarwinProcesses() ([]OSProcessInfo, error) {
	cmd := exec.Command("ps", "-axo", "pid,comm,args")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("darwin process enumeration error: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	var procs []OSProcessInfo

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		name := fields[1]
		cmdline := strings.Join(fields[2:], " ")

		procs = append(procs, OSProcessInfo{
			PID:         pid,
			Name:        name,
			CommandLine: cmdline,
		})
	}

	return procs, nil
}

// normalizeExecutable cleans executable names (stripping .exe, path prefixes) for comparison.
func normalizeExecutable(cmd string) string {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	return base
}

// FindMatch searches the process list for an active process matching command and key arguments.
func (m *OSProcessMatcher) FindMatch(command string, argsSummary string) (bool, int) {
	if len(m.processes) == 0 || command == "" {
		return false, 0
	}

	targetCmd := normalizeExecutable(command)
	argTokens := strings.Fields(argsSummary)

	// Extract meaningful non-flag argument keywords for alignment (e.g. script name, module name)
	var keyArgTokens []string
	for _, tok := range argTokens {
		// Skip flags (e.g. -y, --port, --api-key=...)
		if strings.HasPrefix(tok, "-") {
			continue
		}
		// Clean tokens
		cleaned := strings.Trim(tok, `"'`)
		if len(cleaned) > 2 {
			keyArgTokens = append(keyArgTokens, strings.ToLower(filepath.Base(cleaned)))
		}
	}

	for _, proc := range m.processes {
		if proc.CommandLine == "" {
			continue
		}

		procCmdLineLower := strings.ToLower(proc.CommandLine)
		procNameLower := strings.ToLower(proc.Name)

		// 1. Check command name alignment
		cmdMatches := strings.Contains(procCmdLineLower, targetCmd) || strings.Contains(procNameLower, targetCmd)
		if !cmdMatches {
			continue
		}

		// 2. If command is generic runner (node, python, npx, uvx, bun, deno), require args alignment
		if isGenericRunner(targetCmd) {
			if len(keyArgTokens) == 0 {
				// Cannot safely confirm a generic runner with zero distinctive args
				continue
			}

			// Must match at least one distinctive argument keyword
			matchedArg := false
			for _, keyTok := range keyArgTokens {
				if strings.Contains(procCmdLineLower, keyTok) {
					matchedArg = true
					break
				}
			}

			if matchedArg {
				return true, proc.PID
			}
			continue
		}

		// 3. For specific custom binaries (e.g. my-mcp-server), matching executable is sufficient
		return true, proc.PID
	}

	return false, 0
}

// isGenericRunner identifies generic script/runtime engines that require argument alignment.
func isGenericRunner(cmd string) bool {
	switch cmd {
	case "node", "python", "python3", "npx", "uvx", "uv", "bun", "deno", "ts-node", "ruby", "perl", "powershell", "pwsh", "cmd", "bash", "sh":
		return true
	default:
		return false
	}
}
