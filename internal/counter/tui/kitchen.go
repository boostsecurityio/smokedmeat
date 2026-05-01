// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
)

func (m Model) handleKitchenClientCreated(msg kitchenClientCreatedMsg) (tea.Model, tea.Cmd) {
	m.kitchenClient = msg.client
	m.connected = true
	m.connectionState = "connected"

	cmds := []tea.Cmd{m.startKitchenConsumers()}

	if m.tokenInfo != nil && m.tokenInfo.Owner == "" {
		cmds = append(cmds, m.fetchTokenInfo(m.tokenInfo.Value, m.tokenInfo.Source))
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) startKitchenConsumers() tea.Cmd {
	if m.kitchenClient == nil {
		return func() tea.Msg {
			return KitchenErrorMsg{Err: fmt.Errorf("kitchen client not initialized")}
		}
	}

	m.beaconCh = make(chan counter.Beacon, 10)
	m.coleslawCh = make(chan *models.Coleslaw, 10)
	m.historyCh = make(chan counter.HistoryPayload, 10)
	m.expressDataCh = make(chan counter.ExpressDataPayload, 10)
	m.lootSyncCh = make(chan counter.LootSyncPayload, 4)
	m.analysisProgressCh = make(chan counter.AnalysisProgressPayload, 20)
	m.analysisMetadataCh = make(chan counter.AnalysisMetadataSyncPayload, 8)
	m.authExpiredCh = make(chan struct{}, 1)
	m.reconnectingCh = make(chan int, 10)
	m.reconnectedCh = make(chan struct{}, 1)

	m.kitchenClient.SetCallbacks(
		func(beacon counter.Beacon) {
			select {
			case m.beaconCh <- beacon:
			default:
			}
		},
		func(coleslaw *models.Coleslaw) {
			select {
			case m.coleslawCh <- coleslaw:
			default:
			}
		},
		func(err error) {},
	)

	m.kitchenClient.SetHistoryCallback(func(h counter.HistoryPayload) {
		select {
		case m.historyCh <- h:
		default:
		}
	})

	m.kitchenClient.SetExpressDataCallback(func(data counter.ExpressDataPayload) {
		select {
		case m.expressDataCh <- data:
		default:
		}
	})

	m.kitchenClient.SetLootSyncCallback(func(sync counter.LootSyncPayload) {
		select {
		case m.lootSyncCh <- sync:
		default:
		}
	})

	m.kitchenClient.SetAnalysisProgressCallback(func(progress counter.AnalysisProgressPayload) {
		select {
		case m.analysisProgressCh <- progress:
		default:
		}
	})

	m.kitchenClient.SetAnalysisMetadataSyncCallback(func(sync counter.AnalysisMetadataSyncPayload) {
		select {
		case m.analysisMetadataCh <- sync:
		default:
		}
	})

	m.kitchenClient.SetAuthExpiredCallback(func() {
		select {
		case m.authExpiredCh <- struct{}{}:
		default:
		}
	})

	m.kitchenClient.SetReconnectCallbacks(
		func(attempt int) {
			select {
			case m.reconnectingCh <- attempt:
			default:
			}
		},
		func() {
			select {
			case m.reconnectedCh <- struct{}{}:
			default:
			}
		},
	)

	if err := m.kitchenClient.StartConsuming(); err != nil {
		return func() tea.Msg {
			return KitchenErrorMsg{Err: fmt.Errorf("failed to start Kitchen consumers: %w", err)}
		}
	}

	return tea.Batch(
		func() tea.Msg { return KitchenConnectedMsg{} },
		m.listenForBeacons(),
		m.listenForColeslaw(),
		m.listenForHistory(),
		m.listenForExpressData(),
		m.listenForLootSync(),
		m.listenForAnalysisProgress(),
		m.listenForAnalysisMetadataSync(),
		m.listenForAuthExpired(),
		m.listenForReconnecting(),
		m.listenForReconnected(),
	)
}

func (m *Model) listenForBeacons() tea.Cmd {
	return func() tea.Msg {
		if m.beaconCh == nil {
			return nil
		}
		beacon, ok := <-m.beaconCh
		if !ok {
			return nil
		}
		return BeaconMsg{Beacon: beacon}
	}
}

func (m *Model) listenForColeslaw() tea.Cmd {
	return func() tea.Msg {
		if m.coleslawCh == nil {
			return nil
		}
		coleslaw, ok := <-m.coleslawCh
		if !ok {
			return nil
		}
		return ColeslawMsg{Coleslaw: coleslaw}
	}
}

func (m *Model) listenForHistory() tea.Cmd {
	return func() tea.Msg {
		if m.historyCh == nil {
			return nil
		}
		history, ok := <-m.historyCh
		if !ok {
			return nil
		}
		return HistoryReceivedMsg{History: history}
	}
}

func (m *Model) listenForExpressData() tea.Cmd {
	return func() tea.Msg {
		if m.expressDataCh == nil {
			return nil
		}
		data, ok := <-m.expressDataCh
		if !ok {
			return nil
		}
		return ExpressDataMsg{Data: data}
	}
}

func (m *Model) listenForLootSync() tea.Cmd {
	return func() tea.Msg {
		if m.lootSyncCh == nil {
			return nil
		}
		sync, ok := <-m.lootSyncCh
		if !ok {
			return nil
		}
		return LootSyncMsg{Sync: sync}
	}
}

func (m *Model) listenForAnalysisProgress() tea.Cmd {
	return func() tea.Msg {
		if m.analysisProgressCh == nil {
			return nil
		}
		progress, ok := <-m.analysisProgressCh
		if !ok {
			return nil
		}
		return AnalysisProgressMsg{Progress: progress}
	}
}

func (m *Model) listenForAnalysisMetadataSync() tea.Cmd {
	return func() tea.Msg {
		if m.analysisMetadataCh == nil {
			return nil
		}
		sync, ok := <-m.analysisMetadataCh
		if !ok {
			return nil
		}
		return AnalysisMetadataSyncMsg{Sync: sync}
	}
}

func (m *Model) listenForAuthExpired() tea.Cmd {
	return func() tea.Msg {
		if m.authExpiredCh == nil {
			return nil
		}
		_, ok := <-m.authExpiredCh
		if !ok {
			return nil
		}
		return AuthExpiredMsg{}
	}
}

func (m *Model) listenForReconnecting() tea.Cmd {
	return func() tea.Msg {
		if m.reconnectingCh == nil {
			return nil
		}
		attempt, ok := <-m.reconnectingCh
		if !ok {
			return nil
		}
		return ReconnectingMsg{Attempt: attempt}
	}
}

func (m *Model) listenForReconnected() tea.Cmd {
	return func() tea.Msg {
		if m.reconnectedCh == nil {
			return nil
		}
		_, ok := <-m.reconnectedCh
		if !ok {
			return nil
		}
		return ReconnectedMsg{}
	}
}
