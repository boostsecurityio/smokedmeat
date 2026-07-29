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
		case 'b', 'm', 'r', 'w', 'v', 'n', 'p', 'a', 'f', 'c', 'l':
			state = state.run(action)
		case 'x':
			state = newPrototypeState(state.designIndex)
		case 'q':
			return
		}
	}
}

func render(state prototypeState) {
	design := interfaceDesigns[state.designIndex]
	fmt.Print("\033[2J\033[H")
	fmt.Printf("%sPROTOTYPE - Pantry committed-state transaction%s\n", bold, reset)
	fmt.Printf("%sQuestion: which seam guarantees the transaction while keeping caller knowledge smallest?%s\n\n", dim, reset)

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

	section("Transaction state")
	field("Phase", state.phase)
	field("Writer gate", gateState(state.gateHeld))
	field("Base revision", state.baseRevision)
	field("Candidate edits", state.candidateEdits)
	if state.baseRevision != 0 {
		field("Candidate", state.candidate.summary())
	}
	field("Live Pantry", state.live.summary())
	field("Durable Pantry", state.durable.summary())
	field("Waiting metadata writer", yesNo(state.pendingWriter))
	field("Granular events", state.granularEvents)
	field("Committed-state signals", strings.Join(state.committedSignals, " | "))
	field("Reader observations", strings.Join(state.readerObservations, " | "))
	field("Outcome", state.lastOutcome)

	section("Trace")
	if len(state.trace) == 0 {
		fmt.Printf("   %sBegin a transaction to see the ordering.%s\n", dim, reset)
	}
	for _, line := range state.trace {
		fmt.Printf("   %s\n", line)
	}

	fmt.Printf("\n%sInterfaces:%s [1] raw callback  [2] explicit transaction  [3] scoped Draft callback\n", bold, reset)
	fmt.Printf("%sDrive:%s      [b] begin  [m] mutate candidate  [r] reader  [w] metadata writer  [v] validate/serialize\n", bold, reset)
	fmt.Printf("%sFinish:%s     [n] no-op  [p] persist  [f] persistence failure  [c] cancel before  [a] cancel after store\n", bold, reset)
	fmt.Printf("%sMisuse:%s     [l] leak capability  [x] reset  [q] quit  %sPress a key then Enter.%s\n", bold, reset, dim, reset)
}

func section(title string) {
	fmt.Printf("\n%s%s%s\n", bold, title, reset)
}

func field(name string, value any) {
	fmt.Printf("   %s%s:%s %v\n", bold, name, reset, value)
}

func gateState(held bool) string {
	if held {
		return "held; ordinary writers wait, readers continue"
	}
	return "open"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
