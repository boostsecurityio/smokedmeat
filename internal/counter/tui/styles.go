// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tui implements the Bubbletea-based TUI for the Counter.
package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Palette color vars — set by ApplyTheme()
var (
	primaryColor     color.Color
	secondaryColor   color.Color
	accentColor      color.Color
	fgColor          color.Color
	fgDimColor       color.Color
	mutedColorVal    color.Color
	successColorVal  color.Color
	errorColorVal    color.Color
	warningColorVal  color.Color
	baseBgColor      color.Color
	surfaceColor     color.Color
	cyanColor        color.Color
	purpleColor      color.Color
	purpleDimColor   color.Color
	tealColor        color.Color
	blue1Color       color.Color
	selectionFgColor color.Color
)

// Color styles for direct rendering — set by ApplyTheme()
var (
	mutedColor          lipgloss.Style
	successColor        lipgloss.Style
	errorColor          lipgloss.Style
	warningColor        lipgloss.Style
	secondaryColorStyle lipgloss.Style
)

// Header styles — set by ApplyTheme()
var headerBarStyle lipgloss.Style

var titleStyle lipgloss.Style

var modalTitleStyle lipgloss.Style

var modalBorderStyle lipgloss.Style

// Panel styles — set by ApplyTheme()
var panelTitleStyle lipgloss.Style

// Input styles — set by ApplyTheme()
var (
	inputStyle        lipgloss.Style
	inputFocusedStyle lipgloss.Style
	promptStyle       lipgloss.Style
)

// Output styles — set by ApplyTheme()
var (
	outputStyle lipgloss.Style
)

// Status bar styles — set by ApplyTheme()
var statusBarStyle lipgloss.Style

// Help styles — set by ApplyTheme()
var (
	helpKeyStyle  lipgloss.Style
	helpDescStyle lipgloss.Style
)

// Attack tree styles — set by ApplyTheme()
var (
	treeOrgStyle             lipgloss.Style
	treeRepoStyle            lipgloss.Style
	treePrivateRepoStyle     lipgloss.Style
	treeWorkflowStyle        lipgloss.Style
	treeRunnerStyle          lipgloss.Style
	treeJobStyle             lipgloss.Style
	treeSecretStyle          lipgloss.Style
	treeVulnStyle            lipgloss.Style
	treeCloudStyle           lipgloss.Style
	treeAgentStyle           lipgloss.Style
	treeEphemeralStyle       lipgloss.Style
	treeSelectedStyle        lipgloss.Style
	treeFilterBannerOnStyle  lipgloss.Style
	treeFilterBannerOffStyle lipgloss.Style
	focusIndicatorStyle      lipgloss.Style
)

func init() {
	ApplyTheme(ThemeTokyoNight)
}
