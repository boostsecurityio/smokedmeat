// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
	reset = "\x1b[0m"
)

func main() {
	state := newPrototypeState(0)
	input := bufio.NewScanner(os.Stdin)

	for {
		render(state)
		if !input.Scan() {
			return
		}
		line := strings.TrimSpace(input.Text())
		if line == "" {
			continue
		}
		action := []rune(line)[0]
		switch action {
		case '1', '2', '3':
			state = state.withDesign(int(action - '1'))
		case 'c', 'p', 'g', 'n', 'f':
			state = state.run(action)
		case 'r':
			state = newPrototypeState(state.designIndex)
		case 'q':
			return
		}
	}
}

func render(state prototypeState) {
	design := interfaceDesigns[state.designIndex]
	fmt.Print("\033[2J\033[H")
	fmt.Printf("%sPROTOTYPE - Analysis ingestion interface%s\n", bold, reset)
	fmt.Printf("%sQuestion: which seam gives Kitchen the most depth and least caller burden?%s\n\n", dim, reset)

	section("Selected interface")
	fmt.Printf("%d. %s%s%s\n", state.designIndex+1, bold, design.name, reset)
	for _, line := range design.signature {
		fmt.Printf("   %s\n", line)
	}

	section("Caller")
	for _, line := range design.caller {
		fmt.Printf("   %s\n", line)
	}
	fmt.Printf("   %sCaller must understand:%s %s\n", dim, reset, strings.Join(design.callerMust, ", "))
	fmt.Printf("   %sTradeoff:%s %s\n", dim, reset, design.tradeoff)

	section("Visible state")
	field("Scenario", state.lastScenario)
	field("Outcome", state.lastOutcome)
	field("Live revision", state.liveRevision)
	field("Persisted revision", state.persistedRevision)
	field("Published revision", state.publishedRevision)
	field("Current Pantry", strings.Join(state.assets, " | "))
	field("Durable Loot", strings.Join(state.loot, " | "))
	if state.notice != "" {
		field("Operator notice", state.notice)
	}

	section("Call and commit trace")
	if len(state.trace) == 0 {
		fmt.Printf("   %sRun a scenario to see the trace.%s\n", dim, reset)
	}
	for _, line := range state.trace {
		fmt.Printf("   %s\n", line)
	}

	fmt.Printf("\n%sInterfaces:%s [1] minimal  [2] prepared lifecycle  [3] caller-shaped flow\n", bold, reset)
	fmt.Printf("%sScenarios:%s  [c] commit  [p] partial phases  [g] confirmed gone  [n] no-op  [f] persistence failure\n", bold, reset)
	fmt.Printf("%sControls:%s   [r] reset  [q] quit  %sPress a key then Enter.%s\n", bold, reset, dim, reset)
}

func section(title string) {
	fmt.Printf("\n%s%s%s\n", bold, title, reset)
}

func field(name string, value any) {
	fmt.Printf("   %s%s:%s %v\n", bold, name, reset, value)
}
