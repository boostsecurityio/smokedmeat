// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"image/color"
	"math"

	"charm.land/lipgloss/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
)

type ThemeName string

const (
	ThemeTokyoNight     ThemeName = "tokyo-night"
	ThemeGruvboxDark    ThemeName = "gruvbox-dark"
	ThemeSolarizedLight ThemeName = "solarized-light"
)

type ThemePalette struct {
	Base        color.Color
	Surface     color.Color
	Fg          color.Color
	FgDim       color.Color
	Muted       color.Color
	Primary     color.Color
	Secondary   color.Color
	Accent      color.Color
	Success     color.Color
	Error       color.Color
	Warning     color.Color
	Cyan        color.Color
	Purple      color.Color
	PurpleDim   color.Color
	Teal        color.Color
	Blue1       color.Color
	SelectionFg color.Color
}

var themes = map[ThemeName]ThemePalette{
	ThemeTokyoNight: {
		Base:        lipgloss.Color("#1a1b26"),
		Surface:     lipgloss.Color("#24283b"),
		Fg:          lipgloss.Color("#c0caf5"),
		FgDim:       lipgloss.Color("#a9b1d6"),
		Muted:       lipgloss.Color("#565f89"),
		Primary:     lipgloss.Color("#ff9e64"),
		Secondary:   lipgloss.Color("#7aa2f7"),
		Accent:      lipgloss.Color("#e0af68"),
		Success:     lipgloss.Color("#9ece6a"),
		Error:       lipgloss.Color("#f7768e"),
		Warning:     lipgloss.Color("#e0af68"),
		Cyan:        lipgloss.Color("#7dcfff"),
		Purple:      lipgloss.Color("#bb9af7"),
		PurpleDim:   lipgloss.Color("#9d7cd8"),
		Teal:        lipgloss.Color("#1abc9c"),
		Blue1:       lipgloss.Color("#2ac3de"),
		SelectionFg: lipgloss.Color("#1a1b26"),
	},
	ThemeGruvboxDark: {
		Base:        lipgloss.Color("#282828"),
		Surface:     lipgloss.Color("#3c3836"),
		Fg:          lipgloss.Color("#ebdbb2"),
		FgDim:       lipgloss.Color("#d5c4a1"),
		Muted:       lipgloss.Color("#928374"),
		Primary:     lipgloss.Color("#fe8019"),
		Secondary:   lipgloss.Color("#458588"),
		Accent:      lipgloss.Color("#fabd2f"),
		Success:     lipgloss.Color("#b8bb26"),
		Error:       lipgloss.Color("#fb4934"),
		Warning:     lipgloss.Color("#fabd2f"),
		Cyan:        lipgloss.Color("#83a598"),
		Purple:      lipgloss.Color("#d3869b"),
		PurpleDim:   lipgloss.Color("#b16286"),
		Teal:        lipgloss.Color("#689d6a"),
		Blue1:       lipgloss.Color("#458588"),
		SelectionFg: lipgloss.Color("#282828"),
	},
	ThemeSolarizedLight: {
		Base:        lipgloss.Color("#fdf6e3"),
		Surface:     lipgloss.Color("#eee8d5"),
		Fg:          lipgloss.Color("#657b83"),
		FgDim:       lipgloss.Color("#839496"),
		Muted:       lipgloss.Color("#93a1a1"),
		Primary:     lipgloss.Color("#cb4b16"),
		Secondary:   lipgloss.Color("#268bd2"),
		Accent:      lipgloss.Color("#b58900"),
		Success:     lipgloss.Color("#859900"),
		Error:       lipgloss.Color("#dc322f"),
		Warning:     lipgloss.Color("#b58900"),
		Cyan:        lipgloss.Color("#2aa198"),
		Purple:      lipgloss.Color("#6c71c4"),
		PurpleDim:   lipgloss.Color("#586e75"),
		Teal:        lipgloss.Color("#2aa198"),
		Blue1:       lipgloss.Color("#268bd2"),
		SelectionFg: lipgloss.Color("#fdf6e3"),
	},
}

var activeThemeName ThemeName

func ApplyTheme(name ThemeName) {
	p, ok := themes[name]
	if !ok {
		p = themes[ThemeTokyoNight]
		name = ThemeTokyoNight
	}
	activeThemeName = name

	primaryColor = p.Primary
	secondaryColor = p.Secondary
	accentColor = p.Accent
	fgColor = p.Fg
	fgDimColor = p.FgDim
	mutedColorVal = p.Muted
	successColorVal = p.Success
	errorColorVal = p.Error
	warningColorVal = p.Warning
	baseBgColor = p.Base
	surfaceColor = p.Surface
	cyanColor = p.Cyan
	purpleColor = p.Purple
	purpleDimColor = p.PurpleDim
	tealColor = p.Teal
	blue1Color = p.Blue1
	selectionFgColor = p.SelectionFg

	mutedColor = lipgloss.NewStyle().Foreground(mutedColorVal)
	successColor = lipgloss.NewStyle().Foreground(successColorVal)
	errorColor = lipgloss.NewStyle().Foreground(errorColorVal)
	warningColor = lipgloss.NewStyle().Foreground(warningColorVal)
	secondaryColorStyle = lipgloss.NewStyle().Foreground(secondaryColor)

	headerBarStyle = lipgloss.NewStyle().Background(surfaceColor)

	titleStyle = lipgloss.NewStyle().
		Foreground(primaryColor).
		Bold(true)

	modalTitleStyle = lipgloss.NewStyle().
		Foreground(bestContrastColor(primaryColor, fgColor, baseBgColor)).
		Background(primaryColor).
		Bold(true)

	modalBorderStyle = lipgloss.NewStyle().Foreground(accentColor)

	panelTitleStyle = lipgloss.NewStyle().
		Foreground(secondaryColor).
		Bold(true)

	inputStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mutedColorVal).
		Padding(0, 1)

	inputFocusedStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor).
		Padding(0, 1)

	promptStyle = lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true)

	outputStyle = lipgloss.NewStyle().Foreground(fgColor)

	statusBarStyle = lipgloss.NewStyle().
		Foreground(fgColor).
		Background(baseBgColor).
		Padding(0, 1)

	helpKeyStyle = lipgloss.NewStyle().Foreground(cyanColor).Bold(true)
	helpDescStyle = lipgloss.NewStyle().Foreground(mutedColorVal)

	treeOrgStyle = lipgloss.NewStyle().Foreground(purpleColor).Bold(true)
	treeRepoStyle = lipgloss.NewStyle().Foreground(secondaryColor)
	treePrivateRepoStyle = lipgloss.NewStyle().Foreground(primaryColor).Bold(true)
	treeWorkflowStyle = lipgloss.NewStyle().Foreground(accentColor)
	treeJobStyle = lipgloss.NewStyle().Foreground(cyanColor)
	treeSecretStyle = lipgloss.NewStyle().Foreground(primaryColor)
	treeVulnStyle = lipgloss.NewStyle().Foreground(warningColorVal)
	treeCloudStyle = lipgloss.NewStyle().Foreground(tealColor)
	treeAgentStyle = lipgloss.NewStyle().Foreground(purpleDimColor)
	treeEphemeralStyle = lipgloss.NewStyle().Foreground(warningColorVal).Italic(true)
	treeSelectedStyle = lipgloss.NewStyle().
		Foreground(selectionFgColor).
		Background(blue1Color).
		Bold(true)
	treeFilterBannerOnStyle = lipgloss.NewStyle().
		Foreground(bestContrastColor(successColorVal, fgColor, baseBgColor)).
		Background(successColorVal).
		Bold(true)
	treeFilterBannerOffStyle = lipgloss.NewStyle().
		Foreground(bestContrastColor(secondaryColor, fgColor, baseBgColor)).
		Background(mutedColorVal).
		Bold(true)
	focusIndicatorStyle = lipgloss.NewStyle().Foreground(accentColor)
}

func ThemeNames() []ThemeName {
	return []ThemeName{ThemeTokyoNight, ThemeGruvboxDark, ThemeSolarizedLight}
}

func ActiveTheme() ThemeName {
	return activeThemeName
}

func ThemeLabel(name ThemeName) string {
	switch name {
	case ThemeTokyoNight:
		return "Tokyo Night"
	case ThemeGruvboxDark:
		return "Gruvbox Dark"
	case ThemeSolarizedLight:
		return "Solarized Light"
	default:
		return string(name)
	}
}

func themeDescription(name ThemeName) string {
	switch name {
	case ThemeTokyoNight:
		return "Dark, warm tones"
	case ThemeGruvboxDark:
		return "Dark, warm earth tones"
	case ThemeSolarizedLight:
		return "Light, warm cream"
	default:
		return ""
	}
}

func saveThemeToConfig(name ThemeName) {
	cfg, _ := counter.LoadConfig()
	if cfg == nil {
		cfg = &counter.Config{}
	}
	cfg.Theme = string(name)
	_ = counter.SaveConfig(cfg)
}

func bestContrastColor(bg color.Color, candidates ...color.Color) color.Color {
	if len(candidates) == 0 {
		return color.White
	}

	best := candidates[0]
	bestRatio := contrastRatio(bg, best)
	for _, candidate := range candidates[1:] {
		ratio := contrastRatio(bg, candidate)
		if ratio > bestRatio {
			best = candidate
			bestRatio = ratio
		}
	}
	return best
}

func contrastRatio(a, b color.Color) float64 {
	aLum := relativeLuminance(a)
	bLum := relativeLuminance(b)
	if aLum < bLum {
		aLum, bLum = bLum, aLum
	}
	return (aLum + 0.05) / (bLum + 0.05)
}

func relativeLuminance(c color.Color) float64 {
	r, g, b, _ := c.RGBA()
	return 0.2126*linearizeSRGB(r) + 0.7152*linearizeSRGB(g) + 0.0722*linearizeSRGB(b)
}

func linearizeSRGB(v uint32) float64 {
	channel := float64(v) / 65535.0
	if channel <= 0.04045 {
		return channel / 12.92
	}
	return math.Pow((channel+0.055)/1.055, 2.4)
}
