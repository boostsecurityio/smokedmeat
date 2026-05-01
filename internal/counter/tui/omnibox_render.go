// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

func (m *Model) renderOmniboxOverlay(background string, height int) string {
	if m.omnibox == nil {
		return background
	}

	modalWidth := m.width * 72 / 100
	if modalWidth < 56 {
		modalWidth = m.width - 4
	}
	if modalWidth > m.width-4 {
		modalWidth = m.width - 4
	}

	modal := m.buildOmniboxModal(modalWidth)
	result := compositeTopCenter(modal, dimBackground(background), m.width, height, 2)
	lines := strings.Split(result, "\n")
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", m.width))
	}
	return strings.Join(lines[:height], "\n")
}

func (m *Model) buildOmniboxModal(width int) string {
	innerWidth := width - 2
	lines := []string{
		modalTitleStyle.Width(innerWidth).Render(padRight(" JUMP", innerWidth)),
		padRight(truncateVisual(" "+m.omnibox.input.View(), innerWidth), innerWidth),
		padRight("", innerWidth),
	}

	if len(m.omnibox.results) == 0 {
		lines = append(lines, padRight(mutedColor.Render("  No matches"), innerWidth))
	} else {
		for i, result := range m.omnibox.results {
			labelLine, detailLine := renderOmniboxResult(result, i == m.omnibox.cursor, innerWidth)
			lines = append(lines, labelLine, detailLine)
		}
	}

	lines = append(lines, padRight("", innerWidth))
	hints := helpKeyStyle.Render("↑↓") + helpDescStyle.Render(":select ") +
		helpKeyStyle.Render("Enter") + helpDescStyle.Render(":jump ") +
		helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close")
	lines = append(lines, padRight(truncateVisual(hints, innerWidth), innerWidth))

	body := strings.Join(lines, "\n")
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mutedColorVal).
		Width(width - 2)
	return style.Render(body)
}

func renderOmniboxResult(result OmniboxResult, selected bool, width int) (labelLine, detailLine string) {
	rowBg := color.Color(nil)
	prefixStyle := lipgloss.NewStyle().Foreground(mutedColorVal)
	detailPrefixStyle := lipgloss.NewStyle().Foreground(mutedColorVal)
	labelStyle := lipgloss.NewStyle().Foreground(fgColor)
	detailStyle := lipgloss.NewStyle().Foreground(mutedColorVal)
	spacerStyle := lipgloss.NewStyle()

	labelPrefix := "  "
	detailPrefix := "    "
	if selected {
		rowBg = surfaceColor
		prefixStyle = lipgloss.NewStyle().Foreground(blue1Color).Background(rowBg).Bold(true)
		detailPrefixStyle = lipgloss.NewStyle().Foreground(accentColor).Background(rowBg).Bold(true)
		labelStyle = lipgloss.NewStyle().Foreground(fgColor).Background(rowBg).Bold(true)
		detailStyle = lipgloss.NewStyle().Foreground(fgDimColor).Background(rowBg)
		spacerStyle = spacerStyle.Background(rowBg)
		labelPrefix = "▌ "
		detailPrefix = "│ "
	}

	badge := renderOmniboxKindBadge(result.Kind)
	labelLine = prefixStyle.Render(labelPrefix) +
		badge +
		spacerStyle.Render(" ") +
		labelStyle.Render(result.Label)
	labelLine = truncateVisual(labelLine, width)
	labelLine = padRightWithBackground(labelLine, width, rowBg)

	detailLine = detailPrefixStyle.Render(detailPrefix) + detailStyle.Render(result.Detail)
	detailLine = truncateVisual(detailLine, width)
	detailLine = padRightWithBackground(detailLine, width, rowBg)

	return labelLine, detailLine
}

func renderOmniboxKindBadge(kind OmniboxResultKind) string {
	fg, bg := omniboxKindColors(kind)
	return lipgloss.NewStyle().
		Foreground(fg).
		Background(bg).
		Bold(true).
		Padding(0, 1).
		Render(omniboxKindLabel(kind))
}

func omniboxKindColors(kind OmniboxResultKind) (fg, bg color.Color) {
	fg = selectionFgColor
	if activeThemeName == ThemeSolarizedLight {
		fg = fgColor
	}

	switch kind {
	case OmniboxResultOrg:
		return fg, purpleColor
	case OmniboxResultRepo:
		return fg, secondaryColor
	case OmniboxResultDispatchWorkflow:
		return fg, warningColorVal
	case OmniboxResultWorkflow:
		return fg, accentColor
	case OmniboxResultVuln:
		return fg, errorColorVal
	case OmniboxResultLoot:
		return fg, tealColor
	default:
		return fg, primaryColor
	}
}

func padRightWithBackground(s string, width int, bg color.Color) string {
	visibleWidth := lipgloss.Width(s)
	if visibleWidth >= width {
		return s
	}
	fill := strings.Repeat(" ", width-visibleWidth)
	if bg == nil {
		return s + fill
	}
	return s + lipgloss.NewStyle().Background(bg).Render(fill)
}
