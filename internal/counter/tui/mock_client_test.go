// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package tui

import (
	"context"
	"sync"

	"github.com/boostsecurityio/smokedmeat/internal/counter"
	"github.com/boostsecurityio/smokedmeat/internal/models"
	"github.com/boostsecurityio/smokedmeat/internal/pantry"
)

var _ counter.KitchenAPI = (*mockKitchenClient)(nil)

type mockKitchenClient struct {
	mu        sync.Mutex
	connected bool

	publishOrderErr error

	fetchPantryResp *pantry.Pantry
	fetchPantryErr  error

	fetchHistoryResp    []counter.HistoryPayload
	fetchHistoryErr     error
	recordHistoryErr    error
	fetchCallbacksResp  []counter.CallbackPayload
	fetchCallbacksErr   error
	controlCallbackResp *counter.CallbackPayload
	controlCallbackErr  error

	fetchKnownEntitiesResp []counter.KnownEntityPayload
	fetchKnownEntitiesErr  error
	recordKnownEntityErr   error
	purgeResp              *counter.PurgeResponse
	purgeErr               error

	startConsumingErr error
	reconnectErr      error

	deployPRResp           counter.DeployPRResponse
	deployPRErr            error
	lastDeployPRReq        counter.DeployPRRequest
	deployIssueResp        counter.DeployIssueResponse
	deployIssueErr         error
	lastDeployIssueReq     counter.DeployIssueRequest
	deployCommentResp      counter.DeployCommentResponse
	deployCommentErr       error
	lastDeployCommentReq   counter.DeployCommentRequest
	deployLOTPResp         counter.DeployLOTPResponse
	deployLOTPErr          error
	lastDeployLOTPReq      counter.DeployLOTPRequest
	triggerDispatchErr     error
	lastTriggerDispatchReq counter.DeployDispatchRequest
	fetchPreflightResp     *counter.DeployPreflightResponse
	fetchPreflightErr      error
	lastPreflightReq       counter.DeployPreflightRequest

	listReposWithInfoResp []counter.RepoInfo
	listReposWithInfoErr  error
	listWorkflowsResp     []string
	listWorkflowsErr      error

	getAuthUserResp    counter.GetUserResponse
	getAuthUserErr     error
	fetchTokenInfoResp *counter.FetchTokenInfoResponse
	fetchTokenInfoErr  error

	listAppInstallationsResp  []counter.AppInstallation
	listAppInstallationsErr   error
	createInstTokenResp       *counter.CreateInstallationTokenResponse
	createInstTokenErr        error
	registerCallbackResp      *counter.RegisterCallbackResponse
	registerCallbackErr       error
	lastRegisterCallbackID    string
	lastRegisterCallbackReq   counter.RegisterCallbackRequest
	prepareCachePoisonResp    *counter.PrepareCachePoisonResponse
	prepareCachePoisonErr     error
	lastPrepareCachePoisonReq counter.PrepareCachePoisonRequest

	publishedOrders  []*models.Order
	recordedHistory  []counter.HistoryPayload
	recordedEntities []counter.KnownEntityPayload
}

func (m *mockKitchenClient) PublishOrder(_ context.Context, order *models.Order) error {
	m.publishedOrders = append(m.publishedOrders, order)
	return m.publishOrderErr
}

func (m *mockKitchenClient) FetchPantry(_ context.Context) (*pantry.Pantry, error) {
	return m.fetchPantryResp, m.fetchPantryErr
}

func (m *mockKitchenClient) FetchHistory(_ context.Context, _ int) ([]counter.HistoryPayload, error) {
	return m.fetchHistoryResp, m.fetchHistoryErr
}

func (m *mockKitchenClient) RecordHistory(_ context.Context, entry counter.HistoryPayload) error {
	m.recordedHistory = append(m.recordedHistory, entry)
	return m.recordHistoryErr
}

func (m *mockKitchenClient) FetchCallbacks(_ context.Context, _ string) ([]counter.CallbackPayload, error) {
	return m.fetchCallbacksResp, m.fetchCallbacksErr
}

func (m *mockKitchenClient) ControlCallback(_ context.Context, _ string, _ counter.CallbackControlRequest) (*counter.CallbackPayload, error) {
	return m.controlCallbackResp, m.controlCallbackErr
}

func (m *mockKitchenClient) FetchKnownEntities(_ context.Context, _ string) ([]counter.KnownEntityPayload, error) {
	return m.fetchKnownEntitiesResp, m.fetchKnownEntitiesErr
}

func (m *mockKitchenClient) RecordKnownEntity(_ context.Context, entity counter.KnownEntityPayload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordedEntities = append(m.recordedEntities, entity)
	return m.recordKnownEntityErr
}

func (m *mockKitchenClient) Purge(_ context.Context, _ counter.PurgeRequest) (*counter.PurgeResponse, error) {
	return m.purgeResp, m.purgeErr
}

func (m *mockKitchenClient) StartConsuming() error             { return m.startConsumingErr }
func (m *mockKitchenClient) IsConnected() bool                 { return m.connected }
func (m *mockKitchenClient) Close()                            {}
func (m *mockKitchenClient) Reconnect(_ context.Context) error { return m.reconnectErr }

func (m *mockKitchenClient) DeployPR(_ context.Context, req counter.DeployPRRequest) (counter.DeployPRResponse, error) {
	m.lastDeployPRReq = req
	return m.deployPRResp, m.deployPRErr
}

func (m *mockKitchenClient) DeployIssue(_ context.Context, req counter.DeployIssueRequest) (counter.DeployIssueResponse, error) {
	m.lastDeployIssueReq = req
	return m.deployIssueResp, m.deployIssueErr
}

func (m *mockKitchenClient) DeployComment(_ context.Context, req counter.DeployCommentRequest) (counter.DeployCommentResponse, error) {
	m.lastDeployCommentReq = req
	return m.deployCommentResp, m.deployCommentErr
}

func (m *mockKitchenClient) DeployLOTP(_ context.Context, req counter.DeployLOTPRequest) (counter.DeployLOTPResponse, error) {
	m.lastDeployLOTPReq = req
	return m.deployLOTPResp, m.deployLOTPErr
}

func (m *mockKitchenClient) TriggerDispatch(_ context.Context, req counter.DeployDispatchRequest) error {
	m.lastTriggerDispatchReq = req
	return m.triggerDispatchErr
}

func (m *mockKitchenClient) FetchDeployPreflight(_ context.Context, req counter.DeployPreflightRequest) (*counter.DeployPreflightResponse, error) {
	m.lastPreflightReq = req
	return m.fetchPreflightResp, m.fetchPreflightErr
}

func (m *mockKitchenClient) ListReposWithInfo(_ context.Context, _ string) ([]counter.RepoInfo, error) {
	return m.listReposWithInfoResp, m.listReposWithInfoErr
}

func (m *mockKitchenClient) ListWorkflowsWithDispatch(_ context.Context, _, _, _ string) ([]string, error) {
	return m.listWorkflowsResp, m.listWorkflowsErr
}

func (m *mockKitchenClient) GetAuthenticatedUser(_ context.Context, _ string) (counter.GetUserResponse, error) {
	return m.getAuthUserResp, m.getAuthUserErr
}

func (m *mockKitchenClient) FetchTokenInfo(_ context.Context, _, _ string) (*counter.FetchTokenInfoResponse, error) {
	return m.fetchTokenInfoResp, m.fetchTokenInfoErr
}

func (m *mockKitchenClient) ListAppInstallations(_ context.Context, _, _ string) ([]counter.AppInstallation, error) {
	return m.listAppInstallationsResp, m.listAppInstallationsErr
}

func (m *mockKitchenClient) CreateInstallationToken(_ context.Context, _, _ string, _ int64) (*counter.CreateInstallationTokenResponse, error) {
	return m.createInstTokenResp, m.createInstTokenErr
}

func (m *mockKitchenClient) RegisterCallback(_ context.Context, stagerID string, req counter.RegisterCallbackRequest) (*counter.RegisterCallbackResponse, error) {
	m.lastRegisterCallbackID = stagerID
	m.lastRegisterCallbackReq = req
	return m.registerCallbackResp, m.registerCallbackErr
}

func (m *mockKitchenClient) PrepareCachePoisonDeployment(_ context.Context, req counter.PrepareCachePoisonRequest) (*counter.PrepareCachePoisonResponse, error) {
	m.lastPrepareCachePoisonReq = req
	return m.prepareCachePoisonResp, m.prepareCachePoisonErr
}

func (m *mockKitchenClient) SetCallbacks(_ func(counter.Beacon), _ func(*models.Coleslaw), _ func(error)) {
}
func (m *mockKitchenClient) SetEventCallback(_ func(counter.KitchenEvent))             {}
func (m *mockKitchenClient) SetHistoryCallback(_ func(counter.HistoryPayload))         {}
func (m *mockKitchenClient) SetExpressDataCallback(_ func(counter.ExpressDataPayload)) {}
func (m *mockKitchenClient) SetAnalysisProgressCallback(_ func(counter.AnalysisProgressPayload)) {
}
func (m *mockKitchenClient) SetAnalysisMetadataSyncCallback(_ func(counter.AnalysisMetadataSyncPayload)) {
}
func (m *mockKitchenClient) SetAuthExpiredCallback(_ func())             {}
func (m *mockKitchenClient) SetReconnectCallbacks(_ func(int), _ func()) {}
