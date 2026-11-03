package domain

import "time"

// NodeType indicates the classification of a graph entity.
type NodeType string

const (
	NodeHuman          NodeType = "Human"
	NodeServiceAccount NodeType = "ServiceAccount"
	NodeGroup          NodeType = "Group"
	NodeRole           NodeType = "Role"
	NodeResource       NodeType = "Resource"
	NodeSafeguard      NodeType = "Safeguard"
	NodeSession        NodeType = "Session"
)

// Identity represents a human employee or machine service account.
type Identity struct {
	ID          string            `json:"id"`
	Type        NodeType          `json:"type"`
	DisplayName string            `json:"display_name"`
	Department  string            `json:"department,omitempty"`
	Email       string            `json:"email,omitempty"`
	IsDisabled  bool              `json:"is_disabled"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// Role represents an IAM role with assigned permissions.
type Role struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description,omitempty"`
	Permissions []string          `json:"permissions"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// Resource represents a target system asset.
type Resource struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Tier        int               `json:"tier"` // 0 = Crown Jewel, 1 = High, 2 = Medium, 3 = Low
	DisplayName string            `json:"display_name"`
	Description string            `json:"description,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
}

// Safeguard represents a first-class security control.
type Safeguard struct {
	ID                 string            `json:"id"`
	Tier               int               `json:"tier"`
	DisplayName        string            `json:"display_name"`
	Description        string            `json:"description"`
	ProtectedResources []string          `json:"protected_resources"` // Resource IDs
	Parameters         map[string]string `json:"parameters,omitempty"`
}

// Grant represents an assignment of a role or permission to an identity.
type Grant struct {
	ID          string    `json:"id"`
	IdentityID  string    `json:"identity_id"`
	RoleID      string    `json:"role_id"`
	GrantedAt   time.Time `json:"granted_at"`
	GrantedBy   string    `json:"granted_by"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ControlRelation represents direct or indirect control/takeover between identities.
type ControlRelation struct {
	ControllerID string `json:"controller_id"`
	ControlledID string `json:"controlled_id"`
	Kind         string `json:"kind"` // CAN_ADMINISTER, CAN_ASSUME, PASSWORD_RESET
}

// Session represents an active authenticated session.
type Session struct {
	SessionID  string    `json:"session_id"`
	IdentityID string    `json:"identity_id"`
	DeviceID   string    `json:"device_id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	IsRevoked  bool      `json:"is_revoked"`
}

// TargetAuditEntry records every mutation inside the target system.
type TargetAuditEntry struct {
	Revision   int64             `json:"revision"`
	Timestamp  time.Time         `json:"timestamp"`
	ActorID    string            `json:"actor_id"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	Details    map[string]string `json:"details,omitempty"`
}

// OrgState is the complete snapshot of the simulated exchange organization.
type OrgState struct {
	TenantID         string             `json:"tenant_id"`
	Revision         int64              `json:"revision"`
	Identities       []Identity         `json:"identities"`
	Roles            []Role             `json:"roles"`
	Resources        []Resource         `json:"resources"`
	Safeguards       []Safeguard        `json:"safeguards"`
	Grants           []Grant            `json:"grants"`
	ControlRelations []ControlRelation  `json:"control_relations"`
	Sessions         []Session          `json:"sessions"`
	AuditLog         []TargetAuditEntry `json:"audit_log"`
}
