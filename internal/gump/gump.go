// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package gump

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

type ResultType int

const (
	ResultSecret ResultType = iota
	ResultVar
	ResultTokenPermissions
	ResultEndpoint
)

type Result struct {
	Type             ResultType
	Raw              string
	Secret           Secret
	Var              Var
	TokenPermissions TokenPermissions
	Endpoint         Endpoint
}

type Endpoint struct {
	InternalKey string
	EnvName     string
	Value       string
	Source      string `json:"source,omitempty"`
}

type Scanner interface {
	FindPID() (int, error)
	Scan(pid int, results chan<- Result) error
	ScanWithStats(pid int, results chan<- Result) (ScanStats, error)
}

type ScanStats struct {
	RegionsScanned int
	BytesRead      int64
	ReadErrors     int
}

var (
	secretSuffix     = []byte(`","isSecret":true}`)
	valuePrefix      = []byte(`{"value":"`)
	nullByte         = []byte{0x00}
	permNamePrefix   = []byte(`"system.github.token.permissions"`)
	accessTokenKey   = []byte(`"AccessToken":`)
	varsContextKey   = []byte(`"vars"`)
	dictArrayStart   = []byte(`"d":[`)
	directValueInfix = []byte(`":"`)
	varObjPrefix     = []byte(`{"s":"`)
	varLayouts       = []varLayout{
		{
			namePrefix:     []byte(`{"k":"`),
			valueInfix:     []byte(`","v":`),
			bareValueClose: []byte(`"}`),
			objValueClose:  []byte(`"}}`),
		},
		{
			namePrefix:     []byte(`{"key":"`),
			valueInfix:     []byte(`","value":`),
			bareValueClose: []byte(`"}`),
			objValueClose:  []byte(`"}}`),
		},
		{
			namePrefix:     []byte(`{"name":"`),
			valueInfix:     []byte(`","value":`),
			bareValueClose: []byte(`"}`),
			objValueClose:  []byte(`"}}`),
		},
	}
)

func ScanChunk(data []byte, results chan<- Result) {
	emitter := newResultEmitter(results)
	scanChunkWithEmitter(data, emitter.emit)
}

func scanChunkWithEmitter(data []byte, emit func(Result)) {
	cleanData := data
	if bytes.IndexByte(data, 0x00) >= 0 {
		cleanData = bytes.ReplaceAll(data, nullByte, []byte{})
	}

	scanSecrets(cleanData, emit)
	scanVars(cleanData, emit)
	scanTokenPermissions(cleanData, emit)
	scanRuntimeEndpointObjects(cleanData, emit)
	scanEndpointKeys(cleanData, emit)
}

var (
	systemGitHubTokenPrefix = []byte(`"system.github.token"`)
	gitHubTokenName         = `"GITHUB_TOKEN"`
	kvLayout                = varLayouts[0]

	endpointKeyMappings = []struct {
		needle      []byte
		internalKey string
		envName     string
	}{
		{[]byte(`"CacheServerUrl":`), "CacheServerUrl", "ACTIONS_CACHE_URL"},
		{[]byte(`"ResultsServiceUrl":`), "ResultsServiceUrl", "ACTIONS_RESULTS_URL"},
		{[]byte(`"PipelinesServiceUrl":`), "PipelinesServiceUrl", "ACTIONS_RUNTIME_URL"},
		{[]byte(`"GenerateIdTokenUrl":`), "GenerateIdTokenUrl", "ACTIONS_ID_TOKEN_REQUEST_URL"},
	}

	contextualEndpointKeyMappings = []struct {
		needle      []byte
		internalKey string
		envName     string
	}{
		{accessTokenKey, "AccessToken", "ACTIONS_RUNTIME_TOKEN"},
		{[]byte(`"CacheServerUrl":`), "CacheServerUrl", "ACTIONS_CACHE_URL"},
		{[]byte(`"ResultsServiceUrl":`), "ResultsServiceUrl", "ACTIONS_RESULTS_URL"},
		{[]byte(`"PipelinesServiceUrl":`), "PipelinesServiceUrl", "ACTIONS_RUNTIME_URL"},
		{[]byte(`"GenerateIdTokenUrl":`), "GenerateIdTokenUrl", "ACTIONS_ID_TOKEN_REQUEST_URL"},
	}

	runtimeContextNeedles = [][]byte{
		[]byte(`"ResultsServiceUrl":`),
		[]byte(`"CacheServerUrl":`),
	}
)

type varLayout struct {
	namePrefix     []byte
	valueInfix     []byte
	bareValueClose []byte
	objValueClose  []byte
}

func scanSecrets(cleanData []byte, emit func(Result)) {
	startOffset := 0
	for {
		idx := bytes.Index(cleanData[startOffset:], secretSuffix)
		if idx == -1 {
			break
		}

		actualIdx := startOffset + idx

		lookBackLimit := actualIdx - maxExtractedEntryLen
		if lookBackLimit < 0 {
			lookBackLimit = 0
		}

		precedingSlice := cleanData[lookBackLimit:actualIdx]
		prefixIdx := bytes.LastIndex(precedingSlice, valuePrefix)

		if prefixIdx != -1 {
			nameStart := findNameStart(precedingSlice[:prefixIdx])
			if nameStart >= 0 {
				fullStart := lookBackLimit + nameStart
				fullSecret := string(cleanData[fullStart : actualIdx+len(secretSuffix)])
				if len(fullSecret) <= maxExtractedEntryLen && !isGitHubTokenDuplicate(fullSecret) {
					raw := normalizeSecretName(fullSecret)
					secret, _ := ParseSecret(raw)
					emit(Result{Type: ResultSecret, Raw: raw, Secret: secret})
				}
			}
		}
		startOffset = actualIdx + len(secretSuffix)
	}
}

func isGitHubTokenDuplicate(secret string) bool {
	return bytes.HasPrefix([]byte(secret), []byte(`"github_token"`)) ||
		bytes.HasPrefix([]byte(secret), []byte(`"GITHUB_TOKEN"`))
}

func normalizeSecretName(secret string) string {
	if bytes.HasPrefix([]byte(secret), systemGitHubTokenPrefix) {
		return gitHubTokenName + secret[len(systemGitHubTokenPrefix):]
	}
	return secret
}

func scanVars(cleanData []byte, emit func(Result)) {
	scanVarsContext(cleanData, emit)

	for _, layout := range varLayouts {
		scanEnvLikeObjectEntries(cleanData, layout, emit)
	}
	scanEnvLikeMapEntries(cleanData, emit)
}

func scanVarsContext(cleanData []byte, emit func(Result)) {
	startOffset := 0
	for {
		ctxIdx := bytes.Index(cleanData[startOffset:], varsContextKey)
		if ctxIdx == -1 {
			break
		}

		afterCtx := startOffset + ctxIdx + len(varsContextKey)
		arrIdx := bytes.Index(cleanData[afterCtx:], dictArrayStart)
		if arrIdx == -1 || arrIdx > 32 {
			startOffset = afterCtx
			continue
		}

		pos := afterCtx + arrIdx + len(dictArrayStart)
		scanVarEntries(cleanData, pos, kvLayout, false, emit)
		startOffset = afterCtx
	}
}

func scanVarEntries(cleanData []byte, pos int, layout varLayout, requireEnvLike bool, emit func(Result)) {
	for pos < len(cleanData) {
		for pos < len(cleanData) && (cleanData[pos] == ',' || cleanData[pos] == ' ') {
			pos++
		}
		if pos >= len(cleanData) || cleanData[pos] == ']' {
			return
		}
		fullVar, v, entryEnd, ok := extractObjectVar(cleanData, pos, layout)
		if !ok {
			// Stop at first unparseable entry — caller owns a contiguous array.
			return
		}
		if requireEnvLike && !isEnvLikeName(v.Name) {
			// Stop at first non-env-like name — caller owns a homogeneous array.
			return
		}
		emit(Result{Type: ResultVar, Raw: fullVar, Var: v})
		pos = entryEnd
	}
}

func scanEnvLikeObjectEntries(cleanData []byte, cleanLayout varLayout, emit func(Result)) {
	startOffset := 0
	for {
		idx := bytes.Index(cleanData[startOffset:], cleanLayout.namePrefix)
		if idx == -1 {
			return
		}

		entryStart := startOffset + idx
		fullVar, v, entryEnd, ok := extractObjectVar(cleanData, entryStart, cleanLayout)
		if ok && isEnvLikeName(v.Name) {
			emit(Result{Type: ResultVar, Raw: fullVar, Var: v})
			startOffset = entryEnd
			continue
		}

		startOffset = entryStart + 1
	}
}

func scanEnvLikeMapEntries(cleanData []byte, emit func(Result)) {
	startOffset := 0
	for {
		idx := bytes.IndexByte(cleanData[startOffset:], '"')
		if idx == -1 {
			return
		}

		entryStart := startOffset + idx
		fullVar, v, entryEnd, ok := extractMapVar(cleanData, entryStart)
		if ok {
			emit(Result{Type: ResultVar, Raw: fullVar, Var: v})
			startOffset = entryEnd
			continue
		}

		startOffset = entryStart + 1
	}
}

func scanEndpointKeys(cleanData []byte, emit func(Result)) {
	scanEndpointMappings(cleanData, endpointKeyMappings, emit)
}

func scanRuntimeEndpointObjects(cleanData []byte, emit func(Result)) {
	seenObjects := make(map[[2]int]struct{})
	for _, needle := range runtimeContextNeedles {
		startOffset := 0
		for {
			idx := bytes.Index(cleanData[startOffset:], needle)
			if idx == -1 {
				break
			}

			actualIdx := startOffset + idx
			span, ok := findRuntimeEndpointObject(cleanData, actualIdx)
			if ok {
				if _, seen := seenObjects[span]; !seen {
					seenObjects[span] = struct{}{}
					scanEndpointMappings(cleanData[span[0]:span[1]], contextualEndpointKeyMappings, emit)
				}
			}

			startOffset = actualIdx + 1
		}
	}
}

func scanEndpointMappings(cleanData []byte, mappings []struct {
	needle      []byte
	internalKey string
	envName     string
}, emit func(Result)) {
	for _, mapping := range mappings {
		startOffset := 0
		for {
			idx := bytes.Index(cleanData[startOffset:], mapping.needle)
			if idx == -1 {
				break
			}

			actualIdx := startOffset + idx
			pos := actualIdx + len(mapping.needle)

			for pos < len(cleanData) && (cleanData[pos] == ' ' || cleanData[pos] == '\t') {
				pos++
			}
			if pos >= len(cleanData) || cleanData[pos] != '"' {
				startOffset = actualIdx + 1
				continue
			}

			valueStart := pos + 1
			valueEnd := findStringEnd(cleanData, valueStart, maxExtractedEntryLen)
			if valueEnd == -1 {
				startOffset = actualIdx + 1
				continue
			}

			value := string(cleanData[valueStart:valueEnd])
			if value == "" {
				startOffset = valueEnd + 1
				continue
			}

			raw := string(cleanData[actualIdx : valueEnd+1])
			emit(Result{
				Type: ResultEndpoint,
				Raw:  raw,
				Endpoint: Endpoint{
					InternalKey: mapping.internalKey,
					EnvName:     mapping.envName,
					Value:       value,
				},
			})
			startOffset = valueEnd + 1
		}
	}
}

func findRuntimeEndpointObject(cleanData []byte, pos int) ([2]int, bool) {
	spans := findContainingObjectSpans(cleanData, pos, maxExtractedEntryLen)
	for _, span := range spans {
		objectData := cleanData[span[0]:span[1]]
		if !bytes.Contains(objectData, accessTokenKey) {
			continue
		}
		return span, true
	}
	return [2]int{}, false
}

func findContainingObjectSpans(cleanData []byte, pos, maxLen int) [][2]int {
	lookBackLimit := pos - maxLen
	if lookBackLimit < 0 {
		lookBackLimit = 0
	}

	seen := make(map[[2]int]struct{})
	var spans [][2]int
	for start := pos; start >= lookBackLimit; start-- {
		if cleanData[start] != '{' {
			continue
		}

		end, ok := findObjectEnd(cleanData, start, maxLen)
		if !ok || end <= pos {
			continue
		}

		span := [2]int{start, end}
		if _, exists := seen[span]; exists {
			continue
		}
		seen[span] = struct{}{}
		spans = append(spans, span)
	}

	sort.Slice(spans, func(i, j int) bool {
		iLen := spans[i][1] - spans[i][0]
		jLen := spans[j][1] - spans[j][0]
		if iLen == jLen {
			return spans[i][0] > spans[j][0]
		}
		return iLen < jLen
	})
	return spans
}

func findObjectEnd(cleanData []byte, start, maxLen int) (int, bool) {
	if start < 0 || start >= len(cleanData) || cleanData[start] != '{' {
		return 0, false
	}

	limit := len(cleanData)
	if maxLen > 0 && start+maxLen < limit {
		limit = start + maxLen
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < limit; i++ {
		switch c := cleanData[i]; {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			continue
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}

	return 0, false
}

func extractObjectVar(cleanData []byte, entryStart int, layout varLayout) (raw string, v Var, end int, ok bool) {
	if !bytes.HasPrefix(cleanData[entryStart:], layout.namePrefix) {
		return "", Var{}, 0, false
	}

	nameStart := entryStart + len(layout.namePrefix)
	nameEnd := findStringEnd(cleanData, nameStart, maxExtractedNameLen)
	if nameEnd == -1 {
		return "", Var{}, 0, false
	}

	if !bytes.HasPrefix(cleanData[nameEnd:], layout.valueInfix) {
		return "", Var{}, 0, false
	}

	valueStart := nameEnd + len(layout.valueInfix)
	if valueStart >= len(cleanData) {
		return "", Var{}, 0, false
	}

	var (
		value    string
		entryEnd int
	)
	switch {
	case bytes.HasPrefix(cleanData[valueStart:], varObjPrefix):
		actualValueStart := valueStart + len(varObjPrefix)
		valueEnd := findStringEnd(cleanData, actualValueStart, maxExtractedEntryLen)
		if valueEnd == -1 || !bytes.HasPrefix(cleanData[valueEnd:], layout.objValueClose) {
			return "", Var{}, 0, false
		}
		value = string(cleanData[actualValueStart:valueEnd])
		entryEnd = valueEnd + len(layout.objValueClose)
		ok = true

	case cleanData[valueStart] == '"':
		actualValueStart := valueStart + 1
		valueEnd := findStringEnd(cleanData, actualValueStart, maxExtractedEntryLen)
		if valueEnd == -1 || !bytes.HasPrefix(cleanData[valueEnd:], layout.bareValueClose) {
			return "", Var{}, 0, false
		}
		value = string(cleanData[actualValueStart:valueEnd])
		entryEnd = valueEnd + len(layout.bareValueClose)
		ok = true
	}
	if !ok {
		return "", Var{}, 0, false
	}

	return string(cleanData[entryStart:entryEnd]), Var{
		Name:  string(cleanData[nameStart:nameEnd]),
		Value: value,
	}, entryEnd, true
}

func extractMapVar(cleanData []byte, entryStart int) (raw string, v Var, end int, ok bool) {
	if !hasObjectEntryBoundary(cleanData, entryStart) {
		return "", Var{}, 0, false
	}

	nameStart := entryStart + 1
	nameEnd := findStringEnd(cleanData, nameStart, maxExtractedNameLen)
	if nameEnd == -1 {
		return "", Var{}, 0, false
	}

	name := string(cleanData[nameStart:nameEnd])
	if !isEnvLikeName(name) {
		return "", Var{}, 0, false
	}

	valueStart := nameEnd
	if valueStart >= len(cleanData) {
		return "", Var{}, 0, false
	}

	var (
		value    string
		entryEnd int
	)
	switch {
	case bytes.HasPrefix(cleanData[valueStart:], []byte(`":{"s":"`)):
		actualValueStart := valueStart + len(`":{"s":"`)
		valueEnd := findStringEnd(cleanData, actualValueStart, maxExtractedEntryLen)
		if valueEnd == -1 || !bytes.HasPrefix(cleanData[valueEnd:], []byte(`"}`)) {
			return "", Var{}, 0, false
		}
		value = string(cleanData[actualValueStart:valueEnd])
		entryEnd = valueEnd + len(`"}`)
		ok = true

	case bytes.HasPrefix(cleanData[valueStart:], directValueInfix):
		actualValueStart := valueStart + len(directValueInfix)
		valueEnd := findStringEnd(cleanData, actualValueStart, maxExtractedEntryLen)
		if valueEnd == -1 {
			return "", Var{}, 0, false
		}
		value = string(cleanData[actualValueStart:valueEnd])
		entryEnd = valueEnd + 1
		ok = true
	}
	if !ok {
		return "", Var{}, 0, false
	}
	if !hasObjectEntryTerminator(cleanData, entryEnd) {
		return "", Var{}, 0, false
	}

	return string(cleanData[entryStart:entryEnd]), Var{Name: name, Value: value}, entryEnd, true
}

func hasObjectEntryBoundary(cleanData []byte, entryStart int) bool {
	for i := entryStart - 1; i >= 0; i-- {
		switch cleanData[i] {
		case ' ', '\n', '\r', '\t':
			continue
		case '{', ',':
			return true
		default:
			return false
		}
	}
	return true
}

func hasObjectEntryTerminator(cleanData []byte, entryEnd int) bool {
	for i := entryEnd; i < len(cleanData); i++ {
		switch cleanData[i] {
		case ' ', '\n', '\r', '\t':
			continue
		case ',', '}', ']':
			return true
		default:
			return false
		}
	}
	return true
}

func isEnvLikeName(name string) bool {
	if len(name) < 2 || len(name) > maxExtractedNameLen {
		return false
	}

	hasLetter := false
	hasUnderscore := false
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		case c == '_':
			hasUnderscore = true
		default:
			return false
		}
	}

	return hasLetter && hasUnderscore
}

func findStringEnd(data []byte, start, maxLen int) int {
	limit := len(data)
	if maxLen > 0 && start+maxLen < limit {
		limit = start + maxLen
	}

	escaped := false
	for i := start; i < limit; i++ {
		switch {
		case escaped:
			escaped = false
		case data[i] == '\\':
			escaped = true
		case data[i] == '"':
			return i
		}
	}

	return -1
}

func scanTokenPermissions(cleanData []byte, emit func(Result)) {
	startOffset := 0
	for {
		idx := bytes.Index(cleanData[startOffset:], permNamePrefix)
		if idx == -1 {
			break
		}

		actualIdx := startOffset + idx
		afterName := actualIdx + len(permNamePrefix)

		if afterName >= len(cleanData) {
			break
		}

		valueIdx := bytes.Index(cleanData[afterName:], valuePrefix)
		if valueIdx == -1 || valueIdx > 64 {
			startOffset = afterName
			continue
		}

		valueStart := afterName + valueIdx + len(valuePrefix)
		if valueStart >= len(cleanData) {
			break
		}

		valueEnd := bytes.Index(cleanData[valueStart:], []byte(`}"}`))
		if valueEnd == -1 || valueEnd > maxExtractedEntryLen {
			startOffset = afterName
			continue
		}

		permValue := string(cleanData[valueStart : valueStart+valueEnd+1])
		if permValue != "" && permValue[0] == '{' {
			raw := `"system.github.token.permissions"{"value":"` + permValue + `"}`
			perms, _ := ParseTokenPermissions(raw)
			emit(Result{Type: ResultTokenPermissions, Raw: raw, TokenPermissions: perms})
		}

		startOffset = valueStart + valueEnd
	}
}

func findNameStart(data []byte) int {
	closeQuote := bytes.LastIndex(data, []byte(`"`))
	if closeQuote < 0 {
		return -1
	}
	openQuote := bytes.LastIndex(data[:closeQuote], []byte(`"`))
	if openQuote < 0 {
		return -1
	}
	return openQuote
}

type TokenPermissions map[string]string

const TokenPermissionsPrefix = `"system.github.token.permissions"`

func IsTokenPermissions(result string) bool {
	return strings.HasPrefix(result, TokenPermissionsPrefix)
}

func ParseTokenPermissions(result string) (TokenPermissions, error) {
	if !IsTokenPermissions(result) {
		return nil, fmt.Errorf("not a token permissions result")
	}

	valueStart := strings.Index(result, `{"value":"`)
	if valueStart == -1 {
		return nil, fmt.Errorf("malformed permissions: missing value prefix")
	}
	valueStart += len(`{"value":"`)

	valueEnd := strings.LastIndex(result, `"}`)
	if valueEnd == -1 || valueEnd <= valueStart {
		return nil, fmt.Errorf("malformed permissions: missing value suffix")
	}

	jsonStr := result[valueStart:valueEnd]
	jsonStr = strings.ReplaceAll(jsonStr, `\"`, `"`)

	perms := make(TokenPermissions)
	jsonStr = strings.Trim(jsonStr, "{}")

	if jsonStr == "" {
		return perms, nil
	}

	pairs := splitJSONPairs(jsonStr)
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			key := strings.Trim(kv[0], `"`)
			val := strings.Trim(kv[1], `"`)
			perms[key] = val
		}
	}

	return perms, nil
}

func splitJSONPairs(s string) []string {
	var pairs []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inQuote = !inQuote
		}
		if c == ',' && !inQuote {
			pairs = append(pairs, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		pairs = append(pairs, current.String())
	}
	return pairs
}

type Secret struct {
	Name  string
	Value string
}

func ParseSecret(result string) (Secret, error) {
	if IsTokenPermissions(result) {
		return Secret{}, fmt.Errorf("result is token permissions, not a secret")
	}

	if !strings.HasPrefix(result, `"`) {
		return Secret{}, fmt.Errorf("malformed secret: missing opening quote")
	}

	nameEnd := strings.Index(result[1:], `"`)
	if nameEnd == -1 {
		return Secret{}, fmt.Errorf("malformed secret: missing closing quote for name")
	}
	name := result[1 : nameEnd+1]

	valueStart := strings.Index(result, `{"value":"`)
	if valueStart == -1 {
		return Secret{}, fmt.Errorf("malformed secret: missing value prefix")
	}
	valueStart += len(`{"value":"`)

	valueEnd := strings.Index(result[valueStart:], `"`)
	if valueEnd == -1 {
		return Secret{}, fmt.Errorf("malformed secret: missing value end quote")
	}

	value := result[valueStart : valueStart+valueEnd]

	return Secret{Name: name, Value: value}, nil
}

type Var struct {
	Name  string
	Value string
}

func IsVar(result string) bool {
	_, err := ParseVar(result)
	return err == nil
}

func ParseVar(result string) (Var, error) {
	data := []byte(result)
	for _, layout := range varLayouts {
		if _, v, end, ok := extractObjectVar(data, 0, layout); ok && end == len(data) {
			return v, nil
		}
	}

	if _, v, end, ok := extractMapVar(data, 0); ok && end == len(data) {
		return v, nil
	}

	return Var{}, fmt.Errorf("result is not a var")
}

func EncodeSecrets(secrets map[string]bool) string {
	if len(secrets) == 0 {
		return ""
	}

	var keys []string
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	blob := strings.Join(keys, "\n")
	b64 := base64.StdEncoding.EncodeToString([]byte(blob))
	doubleB64 := base64.StdEncoding.EncodeToString([]byte(b64))

	return doubleB64
}
