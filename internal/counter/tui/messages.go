// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"time"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
	"github.com/boostsecurityio/smokedmeat/internal/poutine"
)

// UI refresh messages

// UITickMsg triggers a UI refresh for animations like flash effects
type UITickMsg struct{}

// Kitchen connection messages (WebSocket to Kitchen C2 server)

// KitchenConnectedMsg indicates Kitchen WebSocket connection was established
type KitchenConnectedMsg struct{}

// KitchenDisconnectedMsg indicates Kitchen WebSocket connection was lost
type KitchenDisconnectedMsg struct{}

// PantryFetchedMsg indicates the attack graph was fetched from Kitchen
type PantryFetchedMsg struct {
	Pantry *pantry.Pantry
}

// PantryFetchErrorMsg indicates a pantry fetch error occurred
type PantryFetchErrorMsg struct {
	Err error
}

// Agent messages

// BeaconMsg is sent when a beacon is received from an agent
type BeaconMsg struct {
	Beacon counter.Beacon
}

// ColeslawMsg is sent when a coleslaw response is received
type ColeslawMsg struct {
	Coleslaw *models.Coleslaw
}

// OrderSentMsg indicates an order was successfully published
type OrderSentMsg struct {
	OrderID string
	AgentID string
}

// OrderFailedMsg indicates an order failed to publish
type OrderFailedMsg struct {
	OrderID string
	Err     error
}

// Analysis messages (pre-agent vulnerability analysis via poutine)

// AnalysisStartedMsg indicates a poutine analysis has started
type AnalysisStartedMsg struct {
	AnalysisID string
	Target     string
	TargetType string
}

type AnalysisProgressMsg struct {
	Progress counter.AnalysisProgressPayload
}

type AnalysisMetadataSyncMsg struct {
	Sync counter.AnalysisMetadataSyncPayload
}

// AnalysisCompletedMsg indicates a poutine analysis completed
type AnalysisCompletedMsg struct {
	AnalysisID string
	Result     *poutine.AnalysisResult
	Deep       bool
}

// AnalysisErrorMsg indicates an analysis error occurred
type AnalysisErrorMsg struct {
	AnalysisID string
	Err        error
}

type AnalysisResponseDroppedMsg struct {
	AnalysisID string
	Deep       bool
	Setup      bool
	Err        error
}

type AnalysisResultStatusFetchedMsg struct {
	AnalysisID string
	Response   *counter.AnalyzeResultStatusResponse
}

type AnalysisResultStatusErrorMsg struct {
	AnalysisID string
	Err        error
}

type PurgePreviewMsg struct {
	Response counter.PurgeResponse
}

type KnownEntitiesFetchedMsg struct {
	Entities []counter.KnownEntityPayload
}

type KnownEntitiesFetchErrorMsg struct {
	Err error
}

type PurgeCompletedMsg struct {
	Response      counter.PurgeResponse
	Pantry        *pantry.Pantry
	KnownEntities []counter.KnownEntityPayload
}

type PurgeErrorMsg struct {
	Err error
}

// Token capability messages

// TokenInfoFetchedMsg indicates token capabilities were successfully fetched
type TokenInfoFetchedMsg struct {
	Info *TokenInfo
}

// TokenInfoErrorMsg indicates token capability fetch failed (token still usable)
type TokenInfoErrorMsg struct {
	Info *TokenInfo
	Err  error
}

type WizardPreflightFetchedMsg struct {
	Key      string
	Response *counter.DeployPreflightResponse
}

type WizardPreflightErrorMsg struct {
	Key string
	Err error
}

// Phase and UI state messages

type TimerTickMsg struct{}

// Auto PR Deployment messages

type AutoPRDeploymentSuccessMsg struct {
	StagerID  string
	PRURL     string
	Vuln      *Vulnerability
	DwellTime time.Duration
}

type AutoPRDeploymentFailedMsg struct {
	StagerID string
	Err      error
}

// Issue Deployment messages

type IssueDeploymentSuccessMsg struct {
	StagerID  string
	IssueURL  string
	Vuln      *Vulnerability
	DwellTime time.Duration
}

type IssueDeploymentFailedMsg struct {
	StagerID string
	Err      error
}

// Comment Deployment messages

type CommentDeploymentSuccessMsg struct {
	StagerID   string
	CommentURL string
	Vuln       *Vulnerability
	DwellTime  time.Duration
}

type CommentDeploymentFailedMsg struct {
	StagerID string
	Err      error
}

// LOTP Deployment messages

type LOTPDeploymentSuccessMsg struct {
	StagerID  string
	PRURL     string
	Vuln      *Vulnerability
	DwellTime time.Duration
}

type LOTPDeploymentFailedMsg struct {
	StagerID string
	Err      error
}

type AutoDispatchSuccessMsg struct {
	StagerID  string
	Vuln      *Vulnerability
	InputName string
	DwellTime time.Duration
}

type AutoDispatchFailedMsg struct {
	StagerID string
	Err      error
}

// Operation History messages

type HistoryFetchedMsg struct {
	Entries []HistoryEntry
}

type HistoryFetchErrorMsg struct {
	Err error
}

type HistoryEntryMsg struct {
	Entry HistoryEntry
}

type HistoryRecordErrorMsg struct {
	Err error
}

// HistoryReceivedMsg is sent when a history entry is received via WebSocket
type HistoryReceivedMsg struct {
	History counter.HistoryPayload
}

type CallbacksFetchedMsg struct {
	Callbacks []counter.CallbackPayload
}

type CallbackFetchErrorMsg struct {
	Err error
}

type CallbackControlSuccessMsg struct {
	Action   string
	Callback counter.CallbackPayload
}

type CallbackControlFailedMsg struct {
	CallbackID string
	Action     string
	Err        error
}

// ExpressDataMsg is sent when express mode secrets are received via WebSocket
type ExpressDataMsg struct {
	Data counter.ExpressDataPayload
}

// Setup wizard messages (steps 5-7)

type SetupTokenAcquiredMsg struct {
	Token       string
	Source      string
	OPSecretRef string
}

type SetupTokenErrorMsg struct {
	Err    error
	Source string
}

type SetupTokenInfoMsg struct {
	Owner  string
	Scopes []string
}

type SetupTokenInfoErrorMsg struct{}

type SetupAnalysisCompletedMsg struct {
	AnalysisID string
	Result     *poutine.AnalysisResult
}

type SetupAnalysisErrorMsg struct {
	AnalysisID string
	Err        error
}

// Connection resilience messages

// AuthExpiredMsg indicates the session token has expired and re-auth is required
type AuthExpiredMsg struct{}

// ReconnectingMsg indicates the client is attempting to reconnect
type ReconnectingMsg struct {
	Attempt int
}

// ReconnectedMsg indicates the client successfully reconnected
type ReconnectedMsg struct{}

// Cloud OIDC pivot messages

// CloudPivotOrderMsg triggers an OIDC pivot order to the active agent.
type CloudPivotOrderMsg struct {
	Provider string
	Config   map[string]string
}

// CloudShellExitMsg is sent when the cloud shell PTY subprocess exits.
type CloudShellExitMsg struct {
	Err error
}

type SSHShellExitMsg struct {
	Err error
}

// Loot export messages

// LootExportedMsg indicates loot export completed
type LootExportedMsg struct {
	Count int
	Err   error
}
