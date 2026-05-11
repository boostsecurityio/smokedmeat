// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var runtimeProbeNames = map[string]string{
	"ACTIONS_RUNTIME_TOKEN":        "AccessToken",
	"ACTIONS_RESULTS_URL":          "ResultsServiceUrl",
	"ACTIONS_CACHE_URL":            "CacheServerUrl",
	"ACTIONS_RUNTIME_URL":          "PipelinesServiceUrl",
	"ACTIONS_CACHE_SERVICE_V2":     "CacheServiceV2",
	"ACTIONS_ID_TOKEN_REQUEST_URL": "GenerateIdTokenUrl",
}

func ProbeRuntimeContext(pid int, results chan<- Result) {
	if results == nil {
		return
	}

	emitter := newResultEmitter(results)
	probeEnvPairs("env", os.Environ(), emitter.emit)
	probeGitHubEnvFile("github-env", os.Getenv("GITHUB_ENV"), emitter.emit)
	probeGitHubEnvFile("github-state", os.Getenv("GITHUB_STATE"), emitter.emit)
	probeProcessEnviron("self-environ", os.Getpid(), emitter.emit)
	probeProcessAncestry(pid, emitter.emit)
}

func probeProcessAncestry(pid int, emit func(Result)) {
	seen := map[int]struct{}{}
	for i := 0; i < 5 && pid > 1; i++ {
		if _, ok := seen[pid]; ok {
			return
		}
		seen[pid] = struct{}{}
		probeProcessEnviron(fmt.Sprintf("proc-%d-environ", pid), pid, emit)
		parent := procParentPID(pid)
		if parent <= 0 || parent == pid {
			return
		}
		pid = parent
	}
}

func probeProcessEnviron(source string, pid int, emit func(Result)) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil || len(data) == 0 {
		return
	}
	parts := bytes.Split(data, []byte{0})
	pairs := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		pairs = append(pairs, string(part))
	}
	probeEnvPairs(source, pairs, emit)
}

func probeEnvPairs(source string, pairs []string, emit func(Result)) {
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		emitRuntimeProbe(source, name, value, emit)
	}
}

func probeGitHubEnvFile(source, path string, emit func(Result)) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	probeEnvFileData(source, string(data), emit)
}

func probeEnvFileData(source, data string, emit func(Result)) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 1024), maxExtractedEntryLen)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if name, delim, ok := strings.Cut(line, "<<"); ok {
			var valueLines []string
			for scanner.Scan() {
				next := scanner.Text()
				if next == delim {
					break
				}
				valueLines = append(valueLines, next)
			}
			emitRuntimeProbe(source, name, strings.Join(valueLines, "\n"), emit)
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		emitRuntimeProbe(source, name, value, emit)
	}
}

func emitRuntimeProbe(source, name, value string, emit func(Result)) {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return
	}
	internalKey, ok := runtimeProbeNames[name]
	if !ok {
		return
	}
	raw := source + ":" + name + "=" + value
	if name == "ACTIONS_CACHE_SERVICE_V2" {
		emit(Result{
			Type: ResultVar,
			Raw:  raw,
			Var:  Var{Name: name, Value: value},
		})
		return
	}
	emit(Result{
		Type: ResultEndpoint,
		Raw:  raw,
		Endpoint: Endpoint{
			InternalKey: internalKey,
			EnvName:     name,
			Value:       value,
			Source:      source,
		},
	})
}

func procParentPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return 0
	}
	parent, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0
	}
	return parent
}
