// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package pantry

// RelationshipType represents edge types in the attack graph.
type RelationshipType string

const (
	// Structural relationships
	RelContains   RelationshipType = "contains" // repo contains workflow
	RelObservedOn RelationshipType = "observed_on"

	// Exposure relationships
	RelExposes      RelationshipType = "exposes"       // workflow exposes secret
	RelGrantsAccess RelationshipType = "grants_access" // token grants access to resource

	// Vulnerability relationships
	RelVulnerableTo RelationshipType = "vulnerable_to" // asset has vulnerability

	// Attack flow relationships
	RelLeadsTo    RelationshipType = "leads_to"    // exploitation leads to next asset
	RelPivotFrom  RelationshipType = "pivot_from"  // lateral movement source
	RelExfilTo    RelationshipType = "exfil_to"    // data exfiltration target
	RelPersistsIn RelationshipType = "persists_in" // persistence location

	// Discovery relationships
	RelDiscoveredBy RelationshipType = "discovered_by" // asset found by agent
	RelScannedBy    RelationshipType = "scanned_by"    // asset scanned by poutine
)

// Relationship represents an edge in the attack graph.
type Relationship struct {
	Type       RelationshipType `json:"type"`
	Properties map[string]any   `json:"properties,omitempty"`
}

// Edge represents a full edge with source and target.
type Edge struct {
	From         string       `json:"from"`
	To           string       `json:"to"`
	Relationship Relationship `json:"relationship"`
}

// NewRelationship creates a new relationship with the given type.
func NewRelationship(relType RelationshipType) Relationship {
	return Relationship{
		Type:       relType,
		Properties: make(map[string]any),
	}
}

// WithProperty adds a property to the relationship and returns it for chaining.
func (r Relationship) WithProperty(key string, value any) Relationship {
	if r.Properties == nil {
		r.Properties = make(map[string]any)
	}
	r.Properties[key] = value
	return r
}

// Contains creates a "contains" relationship.
func Contains() Relationship {
	return NewRelationship(RelContains)
}

func ObservedOn() Relationship {
	return NewRelationship(RelObservedOn)
}

// Exposes creates an "exposes" relationship with optional context.
func Exposes(job, step string) Relationship {
	rel := NewRelationship(RelExposes)
	if job != "" {
		rel.Properties["job"] = job
	}
	if step != "" {
		rel.Properties["step"] = step
	}
	return rel
}

// VulnerableTo creates a "vulnerable_to" relationship with finding context.
func VulnerableTo(ruleID, severity string) Relationship {
	rel := NewRelationship(RelVulnerableTo)
	rel.Properties["rule_id"] = ruleID
	rel.Properties["severity"] = severity
	return rel
}

// DiscoveredBy creates a "discovered_by" relationship.
func DiscoveredBy(agentID string) Relationship {
	rel := NewRelationship(RelDiscoveredBy)
	rel.Properties["agent_id"] = agentID
	return rel
}

// NewEdge creates a full edge with source, target, and relationship.
func NewEdge(from, to string, rel Relationship) Edge {
	return Edge{From: from, To: to, Relationship: rel}
}

// GrantsAccess creates a "grants_access" relationship with scope list.
func GrantsAccess(scopes []string) Relationship {
	rel := NewRelationship(RelGrantsAccess)
	rel.Properties["scopes"] = scopes
	return rel
}

// LeadsTo creates a "leads_to" relationship with technique reference.
func LeadsTo(technique string) Relationship {
	rel := NewRelationship(RelLeadsTo)
	if technique != "" {
		rel.Properties["technique"] = technique
	}
	return rel
}

// ScannedBy creates a "scanned_by" relationship with scanner info.
func ScannedBy(scannerID, scanTime string) Relationship {
	rel := NewRelationship(RelScannedBy)
	rel.Properties["scanner_id"] = scannerID
	rel.Properties["scan_time"] = scanTime
	return rel
}
