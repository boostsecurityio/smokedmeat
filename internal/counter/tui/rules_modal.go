// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

func (m Model) openRulesModal() (Model, tea.Cmd) {
	if cfg, err := counter.LoadConfig(); err == nil && cfg != nil {
		m.config.Poutine = cfg.Poutine
	} else if err != nil {
		m.ruleSummary = nil
		m.ruleSummaryError = "config load failed: " + err.Error()
		m.ruleScroll = 0
		m.prevView = m.view
		m.prevFocus = m.focus
		m.view = ViewRules
		return m, nil
	}

	summary, err := counter.BuildRuleSummary(m.config.Poutine)
	if err != nil {
		m.ruleSummary = nil
		m.ruleSummaryError = "custom rules failed: " + err.Error()
	} else {
		m.ruleSummary = &summary
		m.ruleSummaryError = ""
	}
	m.ruleScroll = 0
	m.prevView = m.view
	m.prevFocus = m.focus
	m.view = ViewRules
	return m, nil
}

func (m Model) handleRulesKeyMsg(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.cleanupCloudSession()
		m.quitting = true
		return m, tea.Quit
	case "esc", "enter", "q", "R", "shift+r":
		m.view = m.prevView
		m.focus = m.prevFocus
		m.updateFocus()
		return m, nil
	case "up", "k":
		m.ruleScroll--
	case "down", "j":
		m.ruleScroll++
	case "pgup", "ctrl+u":
		m.ruleScroll -= 8
	case "pgdown", "ctrl+d":
		m.ruleScroll += 8
	case "home":
		m.ruleScroll = 0
	case "end":
		m.ruleScroll = 1 << 30
	}
	return m, nil
}

func (m *Model) renderRulesOverlay(background string, height int) string {
	modalWidth := min(86, max(m.width-8, 32))
	modalHeight := min(26, max(height-4, 12))

	modal := m.buildRulesModal(modalWidth, modalHeight)
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildRulesModal(width, height int) string {
	contentWidth := max(width-2, 20)
	contentHeight := max(height-2, 8)
	lines := m.rulesModalLines(contentWidth)
	if len(lines) > contentHeight {
		lines = m.visibleRulesModalLines(lines, contentWidth, contentHeight)
	}
	for len(lines) < contentHeight {
		lines = append(lines, strings.Repeat(" ", contentWidth))
	}

	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(warningColorVal).
		Width(contentWidth)

	return style.Render(strings.Join(lines, "\n"))
}

func (m *Model) visibleRulesModalLines(lines []string, width, height int) []string {
	titleLines := min(2, len(lines))
	footerLines := 1
	bodyHeight := max(height-titleLines-footerLines, 1)
	bodyEnd := max(len(lines)-footerLines, titleLines)
	body := lines[titleLines:bodyEnd]
	maxScroll := max(len(body)-bodyHeight, 0)
	if m.ruleScroll < 0 {
		m.ruleScroll = 0
	}
	if m.ruleScroll > maxScroll {
		m.ruleScroll = maxScroll
	}

	out := append([]string(nil), lines[:titleLines]...)
	end := min(m.ruleScroll+bodyHeight, len(body))
	out = append(out, body[m.ruleScroll:end]...)
	for len(out) < height-1 {
		out = append(out, strings.Repeat(" ", width))
	}
	footer := helpKeyStyle.Render("Up/Down") + helpDescStyle.Render(":scroll  ") + helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close")
	if maxScroll > 0 {
		footer = fmt.Sprintf("%s  %d/%d", footer, m.ruleScroll+1, maxScroll+1)
	}
	out = append(out, rulesModalLine(width, footer))
	return out
}

func (m *Model) rulesModalLines(width int) []string {
	lines := []string{
		rulesModalLine(width, modalTitleStyle.Width(width).Render(" ACTIVE RECON RULES")),
		rulesModalLine(width, ""),
	}

	if m.ruleSummaryError != "" {
		lines = append(lines,
			rulesModalLine(width, errorColor.Render("Error")),
			rulesModalLine(width, "  "+m.ruleSummaryError),
			rulesModalLine(width, ""),
			rulesModalLine(width, helpKeyStyle.Render("Esc")+helpDescStyle.Render(":close")),
		)
		return lines
	}
	if m.ruleSummary == nil {
		lines = append(lines,
			rulesModalLine(width, warningColor.Render("No rule summary loaded")),
			rulesModalLine(width, ""),
			rulesModalLine(width, helpKeyStyle.Render("Esc")+helpDescStyle.Render(":close")),
		)
		return lines
	}

	summary := *m.ruleSummary
	customStatus := "enabled"
	if !summary.CustomRulesEnabled {
		customStatus = "disabled by default"
		if summary.CustomRulesExplicit {
			customStatus = "disabled in config"
		}
	}
	pathSuffix := ""
	if summary.CustomRulesDefaultPath {
		pathSuffix = " (default)"
	}
	exists := "missing"
	if summary.CustomRulesPathExists {
		exists = "present"
	}

	lines = append(lines,
		rulesModalLine(width, secondaryColorStyle.Render("Config")),
		rulesModalLine(width, "  file: "+summary.ConfigPath),
		rulesModalLine(width, "  custom_rules: "+customStatus),
		rulesModalLine(width, "  path: "+summary.CustomRulesPath+pathSuffix+" ["+exists+"]"),
		rulesModalLine(width, ""),
		rulesModalLine(width, secondaryColorStyle.Render("Effective Rules")),
		rulesModalLine(width, fmt.Sprintf("  built-in poutine: %s", enabledLabel(len(summary.BuiltinRules) > 0))),
	)
	if len(summary.BuiltinRules) == 0 {
		lines = append(lines, rulesModalLine(width, "    none"))
	} else {
		for _, rule := range summary.BuiltinRules {
			lines = append(lines, rulesModalLine(width, "    "+rule))
		}
	}

	lines = append(lines, rulesModalLine(width, fmt.Sprintf("  custom rego: %d file(s)", len(summary.CustomRuleFiles))))
	if len(summary.CustomRuleFiles) == 0 {
		lines = append(lines, rulesModalLine(width, "    none"))
	} else {
		for _, file := range summary.CustomRuleFiles {
			lines = append(lines, rulesModalLine(width, "    "+file))
		}
	}

	lines = append(lines,
		rulesModalLine(width, ""),
		rulesModalLine(width, secondaryColorStyle.Render("Exploit Mapping")),
	)
	if len(summary.RuleMappings) == 0 {
		lines = append(lines, rulesModalLine(width, "  no explicit mappings"))
	} else {
		for _, mapping := range summary.RuleMappings {
			class := mapping.ExploitClass
			if class == "" {
				class = "(default)"
			}
			lines = append(lines, rulesModalLine(width, "  "+mapping.RuleID+" -> "+class))
		}
	}
	lines = append(lines,
		rulesModalLine(width, "  unmapped custom rules -> "+summary.UnmappedRuleDefault),
		rulesModalLine(width, ""),
		rulesModalLine(width, helpKeyStyle.Render("Esc")+helpDescStyle.Render(":close  ")+helpKeyStyle.Render("R")+helpDescStyle.Render(":close")),
	)

	return lines
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func rulesModalLine(width int, line string) string {
	line = truncateVisual(line, width)
	pad := width - lipgloss.Width(line)
	if pad < 0 {
		pad = 0
	}
	return line + strings.Repeat(" ", pad)
}
