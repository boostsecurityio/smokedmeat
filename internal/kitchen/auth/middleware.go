// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

// ContextKey is the type for context keys.
type ContextKey string

const (
	// ClaimsKey is the context key for JWT claims.
	ClaimsKey ContextKey = "claims"
	// AgentClaimsKey is the context key for agent claims.
	AgentClaimsKey ContextKey = "agent_claims"
	// AgentTokenHeader is the HTTP header for agent authentication.
	AgentTokenHeader = "X-Agent-Token"
	// OperatorTokenCookie is the cookie used by browser-only operator pages.
	OperatorTokenCookie = "smokedmeat_operator"
)

// StagerValidator validates stager IDs. Implemented by StagerStore.
type StagerValidator interface {
	ValidateStager(id string) (sessionID string, expired bool, exists bool)
}

// extractToken gets the JWT token from the request.
func extractToken(r *http.Request) string {
	// Check Authorization header first
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Check query param (useful for WebSocket connections)
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	if cookie, err := r.Cookie(OperatorTokenCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

// RequireOperatorAuth validates operator JWT and logs failures to audit.
func RequireOperatorAuth(auth *Auth, audit AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)

			if token == "" {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventAuthFailure, PrincipalUnknown, "missing token"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := auth.ValidateToken(token)
			if err != nil {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventAuthFailure, PrincipalOperator, "invalid token"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAgentAuth validates agent token via X-Agent-Token header.
func RequireAgentAuth(auth *Auth, audit AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get(AgentTokenHeader)

			slog.Info("agent auth check",
				"path", r.URL.Path,
				"token_present", token != "",
				"token_len", len(token),
				"user_agent", r.UserAgent(),
			)

			if token == "" {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventAgentTokenInvalid, PrincipalAgent, "missing agent token"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := auth.ValidateAgentToken(token)
			if err != nil {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventAgentTokenInvalid, PrincipalAgent, "invalid agent token"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), AgentClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireStagerAuth validates stager ID from URL path.
// Returns opaque 401 for all failures to prevent information leakage.
func RequireStagerAuth(validator StagerValidator, audit AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stagerID := r.PathValue("stagerID")
			if stagerID == "" {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventStagerNotFound, PrincipalStager, "missing stager ID"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			_, expired, exists := validator.ValidateStager(stagerID)
			if !exists {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventStagerNotFound, PrincipalStager, "unknown stager ID"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if expired {
				audit.LogSecurityEvent(NewSecurityEventFromRequest(r, EventStagerExpired, PrincipalStager, "stager expired"))
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
