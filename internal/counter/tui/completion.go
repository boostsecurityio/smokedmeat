// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"os/exec"
	"sort"
	"strings"
)

var alwaysCommands = []string{"help", "license", "quit"}

func commandsForPhase(phase Phase) []string {
	cmds := append([]string{}, alwaysCommands...)
	switch phase {
	case PhaseSetup:
		cmds = append(cmds, "set", "analyze", "deep-analyze", "status")
	case PhaseRecon:
		cmds = append(cmds, "implants", "exploit", "graph", "pivot", "purge", "ssh", "set", "analyze", "deep-analyze", "status", "use")
	case PhaseWizard, PhaseWaiting:
		// no extras
	case PhasePostExploit, PhasePivot:
		cmds = append(cmds, "implants", "order", "select", "sessions", "graph", "set", "status",
			"pivot", "purge", "ssh", "cloud", "analyze", "deep-analyze", "exploit", "use")
	}
	sort.Strings(cmds)
	return cmds
}

var setSubcommands = []string{
	"token",
	"target",
	"activity-log",
}

var tokenSubcommands = []string{
	"op",
	"gh",
	"<PAT>",
}

func (m *Model) getCompletions(input string) []string {
	hasTrailingSpace := strings.HasSuffix(input, " ")
	input = strings.TrimSpace(input)
	parts := strings.Fields(input)

	available := commandsForPhase(m.phase)

	if len(parts) == 0 {
		return available
	}

	if len(parts) == 1 && !hasTrailingSpace {
		prefix := strings.ToLower(parts[0])
		var matches []string
		for _, cmd := range available {
			if strings.HasPrefix(cmd, prefix) {
				matches = append(matches, cmd)
			}
		}
		sort.Strings(matches)
		return matches
	}

	if parts[0] == "set" {
		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			var matches []string
			for _, sub := range setSubcommands {
				if strings.HasPrefix(sub, prefix) {
					matches = append(matches, "set "+sub)
				}
			}
			return matches
		}

		if len(parts) >= 2 && parts[1] == "token" {
			if len(parts) == 2 || (len(parts) == 3 && !hasTrailingSpace) {
				prefix := ""
				if len(parts) == 3 {
					prefix = strings.ToLower(parts[2])
				}
				var matches []string
				for _, sub := range tokenSubcommands {
					if strings.HasPrefix(sub, prefix) {
						matches = append(matches, "set token "+sub)
					}
				}
				return matches
			}
		}

		if len(parts) >= 2 && parts[1] == "target" {
			if len(parts) == 2 || (len(parts) == 3 && !hasTrailingSpace) {
				prefix := ""
				if len(parts) == 3 {
					prefix = strings.ToLower(parts[2])
				}
				return m.targetCompletions(prefix)
			}
		}

		if len(parts) >= 2 && parts[1] == "activity-log" {
			if len(parts) == 2 || (len(parts) == 3 && !hasTrailingSpace) {
				prefix := ""
				if len(parts) == 3 {
					prefix = strings.ToLower(parts[2])
				}
				if strings.HasPrefix(prefix, "autoexpand") {
					return []string{"set activity-log autoexpand"}
				}
				return nil
			}
			if len(parts) == 3 || (len(parts) == 4 && !hasTrailingSpace) {
				prefix := ""
				if len(parts) == 4 {
					prefix = strings.ToLower(parts[3])
				}
				var matches []string
				for _, opt := range []string{"on", "off"} {
					if strings.HasPrefix(opt, prefix) {
						matches = append(matches, "set activity-log autoexpand "+opt)
					}
				}
				return matches
			}
		}
	}

	if parts[0] == "pivot" {
		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			subs := []string{"github", "app", "ssh", "aws", "gcp", "azure"}
			var matches []string
			for _, sub := range subs {
				if strings.HasPrefix(sub, prefix) {
					matches = append(matches, "pivot "+sub)
				}
			}
			return matches
		}
		if len(parts) >= 2 && parts[1] == "ssh" {
			if len(parts) == 2 || (len(parts) == 3 && !hasTrailingSpace) {
				prefix := ""
				if len(parts) == 3 {
					prefix = strings.ToLower(parts[2])
				}
				var matches []string
				if target := m.currentTargetSpec(); target != "" && strings.HasPrefix(strings.ToLower(target), prefix) {
					matches = append(matches, "pivot ssh "+target)
				}
				for _, opt := range []string{"org:", "repo:"} {
					if strings.HasPrefix(opt, prefix) {
						matches = append(matches, "pivot ssh "+opt)
					}
				}
				sort.Strings(matches)
				return matches
			}
		}
	}

	if parts[0] == "cloud" {
		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			seen := map[string]bool{}
			var matches []string
			for _, sub := range []string{"status", "shell", "export"} {
				if strings.HasPrefix(sub, prefix) {
					matches = append(matches, "cloud "+sub)
					seen[sub] = true
				}
			}
			if m.cloudState != nil {
				provider := m.cloudState.Provider
				for name := range nativeCloudQueries[provider] {
					if !seen[name] && strings.HasPrefix(name, prefix) {
						matches = append(matches, "cloud "+name)
						seen[name] = true
					}
				}
			}
			sort.Strings(matches)
			return matches
		}
	}

	if parts[0] == "ssh" {
		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			var matches []string
			for _, sub := range []string{"status", "shell"} {
				if strings.HasPrefix(sub, prefix) {
					matches = append(matches, "ssh "+sub)
				}
			}
			sort.Strings(matches)
			return matches
		}
	}

	if parts[0] == "order" {
		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			var matches []string
			for _, sub := range orderSubcommands {
				if strings.HasPrefix(sub, prefix) {
					matches = append(matches, "order "+sub)
				}
			}
			return matches
		}
	}

	if parts[0] == "purge" {
		base := "purge"
		offset := 1
		if len(parts) > 1 && parts[1] == "confirm" {
			base = "purge confirm"
			offset = 2
		}

		if len(parts) == 1 || (len(parts) == 2 && !hasTrailingSpace && offset == 1) {
			prefix := ""
			if len(parts) == 2 {
				prefix = strings.ToLower(parts[1])
			}
			var matches []string
			if strings.HasPrefix("confirm", prefix) {
				matches = append(matches, "purge confirm")
			}
			for _, spec := range m.purgeTargetSpecs() {
				candidate := "purge " + spec
				if strings.HasPrefix(strings.ToLower(candidate), "purge "+prefix) {
					matches = append(matches, candidate)
				}
			}
			sort.Strings(matches)
			return compactStrings(matches)
		}

		if len(parts) == offset || (len(parts) == offset+1 && !hasTrailingSpace) {
			prefix := ""
			if len(parts) == offset+1 {
				prefix = strings.ToLower(parts[offset])
			}
			var matches []string
			for _, spec := range m.purgeTargetSpecs() {
				candidate := base + " " + spec
				if strings.HasPrefix(strings.ToLower(candidate), base+" "+prefix) {
					matches = append(matches, candidate)
				}
			}
			sort.Strings(matches)
			return compactStrings(matches)
		}
	}

	if parts[0] == "select" && len(m.sessions) > 0 {
		prefix := ""
		if len(parts) == 2 {
			prefix = parts[1]
		}
		var matches []string
		for _, s := range m.sessions {
			if strings.HasPrefix(s.AgentID, prefix) {
				matches = append(matches, "select "+s.AgentID)
			}
		}
		return matches
	}

	return nil
}

func (m *Model) completeInput() bool {
	input := m.input.Value()
	completions := m.getCompletions(input)

	if len(completions) == 0 {
		if hint := orderCompletionHint(input); hint != "" {
			m.completionHint = hint
			return true
		}
		m.completionHint = ""
		return false
	}

	if len(completions) == 1 {
		completion := completions[0]
		// Don't add space after completions ending with : (user needs to type value)
		if !strings.HasSuffix(completion, ":") {
			completion += " "
		}
		m.input.SetValue(completion)
		m.input.CursorEnd()
		m.completionHint = ""
		return true
	}

	common := longestCommonPrefix(completions)
	if len(common) > len(strings.TrimSpace(input)) {
		m.input.SetValue(common)
		m.input.CursorEnd()
	}

	// Special hint for target completions with examples
	if strings.HasPrefix(common, "set target ") {
		m.completionHint = "org:acme-corp  repo:acme-corp/api"
		return true
	}

	if hint := orderCompletionListHint(input, completions); hint != "" {
		m.completionHint = hint
		return true
	}

	// Show just the varying part as hint (strip common prefix)
	hints := make([]string, len(completions))
	for i, c := range completions {
		hints[i] = strings.TrimPrefix(c, common)
		if hints[i] == "" {
			hints[i] = c
		}
	}
	m.completionHint = strings.Join(hints, "  ")
	return true
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	prefix := strs[0]
	for _, s := range strs[1:] {
		for prefix != "" && !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}

func orderCompletionHint(input string) string {
	hasTrailingSpace := strings.HasSuffix(input, " ")
	parts := strings.Fields(strings.TrimSpace(input))
	if len(parts) < 2 || parts[0] != "order" {
		return ""
	}
	if !hasTrailingSpace && len(parts) == 2 {
		return ""
	}
	hint, ok := orderSubcommandHints[parts[1]]
	if !ok {
		return ""
	}
	return hint
}

func orderCompletionListHint(input string, completions []string) string {
	if !strings.HasPrefix(strings.TrimSpace(input), "order") {
		return ""
	}
	hints := make([]string, 0, len(completions))
	for _, completion := range completions {
		parts := strings.Fields(completion)
		if len(parts) != 2 || parts[0] != "order" {
			return ""
		}
		hint, ok := orderSubcommandHints[parts[1]]
		if !ok {
			return ""
		}
		hints = append(hints, hint)
	}
	return strings.Join(hints, "  ")
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]bool, len(values))
	result := values[:0]
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func (m *Model) purgeTargetSpecs() []string {
	specs := append([]string{}, m.discoveredTargetSpecs()...)
	if target := m.currentTargetSpec(); target != "" {
		specs = append(specs, target)
	}
	sort.Strings(specs)
	return compactStrings(specs)
}

func (m *Model) targetCompletions(prefix string) []string {
	if !strings.Contains(prefix, ":") {
		var matches []string
		for _, opt := range []string{"org:", "repo:"} {
			if strings.HasPrefix(opt, prefix) {
				matches = append(matches, "set target "+opt)
			}
		}
		return matches
	}

	var matches []string
	for _, spec := range m.discoveredTargetSpecs() {
		if strings.HasPrefix(strings.ToLower(spec), prefix) {
			matches = append(matches, "set target "+spec)
		}
	}
	if len(matches) == 0 {
		switch {
		case strings.HasPrefix(prefix, "org:"):
			return []string{"set target org:"}
		case strings.HasPrefix(prefix, "repo:"):
			return []string{"set target repo:"}
		}
	}
	sort.Strings(matches)
	return matches
}

func (m *Model) discoveredTargetSpecs() []string {
	seen := map[string]bool{}
	var specs []string

	add := func(spec string) {
		spec = strings.TrimSpace(spec)
		if spec == "" || seen[spec] {
			return
		}
		seen[spec] = true
		specs = append(specs, spec)
	}

	add(m.currentTargetSpec())

	var walk func(*TreeNode)
	walk = func(node *TreeNode) {
		if node == nil {
			return
		}
		switch node.Type {
		case TreeNodeOrg:
			if org := m.treeNodeOrg(node); org != "" {
				add("org:" + org)
			}
		case TreeNodeRepo:
			if repo := m.treeNodeRepo(node); repo != "" {
				add("repo:" + repo)
			}
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(m.treeRoot)

	for _, entity := range m.knownEntities {
		if entity == nil || entity.Name == "" {
			continue
		}
		switch entity.EntityType {
		case "org":
			add("org:" + entity.Name)
		case "repo":
			add("repo:" + entity.Name)
		}
	}

	sort.Strings(specs)
	return specs
}

func (m *Model) getContextualPlaceholder() string {
	if m.config.KitchenURL == "" {
		return "set kitchen https://kitchen.example.com"
	}

	if m.tokenInfo == nil {
		return "set token  (press Tab for options)"
	}

	if m.target == "" {
		return "set target org:your-org"
	}

	if len(m.vulnerabilities) == 0 {
		return "analyze"
	}

	if m.selectedVuln < 0 {
		return "use V001  (select a vulnerability)"
	}

	return "payload  (generate injection payload)"
}

func hasOPCLI() bool {
	_, err := exec.LookPath("op")
	return err == nil
}

func hasGHCLI() bool {
	_, err := exec.LookPath("gh")
	return err == nil
}
