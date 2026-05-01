// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AgentRow represents an agent record in the database.
type AgentRow struct {
	AgentID        string     `json:"agent_id"`
	SessionID      string     `json:"session_id"`
	Hostname       string     `json:"hostname"`
	OS             string     `json:"os"`
	Arch           string     `json:"arch"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	IsOnline       bool       `json:"is_online"`
	DwellDeadline  *time.Time `json:"dwell_deadline,omitempty"`
	AgentToken     string     `json:"agent_token,omitempty"`
	TokenCreatedAt time.Time  `json:"agent_token_created_at,omitempty"`
	TokenExpiresAt time.Time  `json:"agent_token_expires_at,omitempty"`
}

// SessionRow represents a session record in the database.
type SessionRow struct {
	ID            string     `json:"id"`
	Target        string     `json:"target"`
	ThreatModel   string     `json:"threat_model"`
	CreatedAt     time.Time  `json:"created_at"`
	DwellDeadline *time.Time `json:"dwell_deadline,omitempty"`
}

// AgentRepository provides database operations for agents.
type AgentRepository struct {
	db *DB
}

// NewAgentRepository creates a new AgentRepository.
func NewAgentRepository(db *DB) *AgentRepository {
	return &AgentRepository{db: db}
}

// Upsert inserts or updates an agent in the database.
func (r *AgentRepository) Upsert(agent *AgentRow) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAgents)

		existing := b.Get([]byte(agent.AgentID))
		if existing != nil {
			var existingAgent AgentRow
			if err := json.Unmarshal(existing, &existingAgent); err == nil {
				if agent.FirstSeen.IsZero() {
					agent.FirstSeen = existingAgent.FirstSeen
				}
				if agent.LastSeen.IsZero() {
					agent.LastSeen = existingAgent.LastSeen
				}
				if agent.DwellDeadline == nil {
					agent.DwellDeadline = existingAgent.DwellDeadline
				}
				if agent.AgentToken == "" {
					agent.AgentToken = existingAgent.AgentToken
					agent.TokenCreatedAt = existingAgent.TokenCreatedAt
					agent.TokenExpiresAt = existingAgent.TokenExpiresAt
				}
			}
		}

		data, err := json.Marshal(agent)
		if err != nil {
			return fmt.Errorf("failed to marshal agent: %w", err)
		}

		return b.Put([]byte(agent.AgentID), data)
	})
}

// Get retrieves an agent by ID.
func (r *AgentRepository) Get(agentID string) (*AgentRow, error) {
	var agent *AgentRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAgents)
		data := b.Get([]byte(agentID))
		if data == nil {
			return nil
		}

		agent = &AgentRow{}
		return json.Unmarshal(data, agent)
	})

	return agent, err
}

// List retrieves all agents.
func (r *AgentRepository) List() ([]*AgentRow, error) {
	var agents []*AgentRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAgents)

		return b.ForEach(func(k, v []byte) error {
			var agent AgentRow
			if err := json.Unmarshal(v, &agent); err != nil {
				return err
			}
			agents = append(agents, &agent)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by LastSeen descending
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].LastSeen.After(agents[j].LastSeen)
	})

	return agents, nil
}

// SetDwellDeadline sets the dwell deadline for all agents in a session.
func (r *AgentRepository) SetDwellDeadline(sessionID string, deadline *time.Time) error {
	return r.db.bolt.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketAgents)

		return b.ForEach(func(k, v []byte) error {
			var agent AgentRow
			if err := json.Unmarshal(v, &agent); err != nil {
				return err
			}

			if agent.SessionID == sessionID {
				agent.DwellDeadline = deadline
				data, err := json.Marshal(agent)
				if err != nil {
					return err
				}
				return b.Put([]byte(agent.AgentID), data)
			}
			return nil
		})
	})
}

// SessionRepository provides database operations for sessions.
type SessionRepository struct {
	db *DB
}

// NewSessionRepository creates a new SessionRepository.
func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// List retrieves all sessions.
func (r *SessionRepository) List() ([]*SessionRow, error) {
	var sessions []*SessionRow

	err := r.db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(BucketSessions)

		return b.ForEach(func(k, v []byte) error {
			var session SessionRow
			if err := json.Unmarshal(v, &session); err != nil {
				return err
			}
			sessions = append(sessions, &session)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by CreatedAt descending
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
	})

	return sessions, nil
}
