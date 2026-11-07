package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

var ErrRevision = errors.New("target revision conflict")

type TargetCommand struct {
	CommandID              string `json:"command_id"`
	TenantID               string `json:"tenant_id"`
	Action                 string `json:"action"`
	TargetIdentity         string `json:"target_identity"`
	ResourceOrRole         string `json:"resource_or_role"`
	ExpectedTargetRevision int64  `json:"expected_target_revision"`
}
type CommandReceipt struct {
	Command        TargetCommand `json:"command"`
	Revision       int64         `json:"revision"`
	CurrentRoles   []string      `json:"current_roles"`
	ActiveSessions []string      `json:"active_sessions"`
	IsRestricted   bool          `json:"is_restricted"`
	AppliedAt      time.Time     `json:"applied_at"`
}

func (r CommandReceipt) clone() CommandReceipt {
	r.CurrentRoles = slices.Clone(r.CurrentRoles)
	r.ActiveSessions = slices.Clone(r.ActiveSessions)
	return r
}

// Execute serializes CAS, the mutation and its durable duplicate receipt under
// the target's own lock. Failed persistence rolls back the visible in-memory state.
func (s *Store) Execute(command TargetCommand) (CommandReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if command.CommandID == "" || len(command.CommandID) > 128 || command.TenantID != s.state.TenantID {
		return CommandReceipt{}, errors.New("bound command and tenant required")
	}
	if old, ok := s.state.CommandReceipts[command.CommandID]; ok {
		if old.Command != command {
			return CommandReceipt{}, errors.New("command identity reused with different intent")
		}
		return old.clone(), nil
	}
	if command.ExpectedTargetRevision < 1 || command.ExpectedTargetRevision != s.state.Revision {
		return CommandReceipt{}, ErrRevision
	}
	if len(s.state.CommandReceipts) >= 100000 {
		return CommandReceipt{}, errors.New("durable command receipt capacity reached")
	}
	raw, err := json.Marshal(s.state)
	if err != nil {
		return CommandReceipt{}, err
	}
	candidate := &Store{}
	if err = json.Unmarshal(raw, &candidate.state); err != nil {
		return CommandReceipt{}, err
	}
	const actor = "broker:ratchet-connector"
	switch command.Action {
	case "ASSIGN_ROLE":
		err = candidate.AssignRole(actor, command.TargetIdentity, command.ResourceOrRole)
	case "REVOKE_ROLE", "REMOVE_SERVICE_PERMISSION":
		err = candidate.RevokeRole(actor, command.TargetIdentity, command.ResourceOrRole)
	case "TERMINATE_SESSION":
		owned := false
		for _, session := range candidate.state.Sessions {
			if session.SessionID == command.ResourceOrRole && session.IdentityID == command.TargetIdentity {
				owned = true
			}
		}
		if !owned {
			return CommandReceipt{}, errors.New("session owner mismatch")
		}
		err = candidate.TerminateSession(actor, command.ResourceOrRole)
	case "RESTRICT_ACCOUNT":
		err = candidate.RestrictAccount(actor, command.TargetIdentity)
	default:
		err = fmt.Errorf("unsupported action %q", command.Action)
	}
	if err != nil {
		return CommandReceipt{}, err
	}
	receipt := CommandReceipt{Command: command, Revision: candidate.state.Revision, AppliedAt: time.Now().UTC()}
	for _, grant := range candidate.state.Grants {
		if grant.IdentityID == command.TargetIdentity {
			receipt.CurrentRoles = append(receipt.CurrentRoles, grant.RoleID)
		}
	}
	for _, session := range candidate.state.Sessions {
		if session.IdentityID == command.TargetIdentity && !session.IsRevoked {
			receipt.ActiveSessions = append(receipt.ActiveSessions, session.SessionID)
		}
	}
	for _, identity := range candidate.state.Identities {
		if identity.ID == command.TargetIdentity {
			receipt.IsRestricted = identity.IsDisabled
		}
	}
	if candidate.state.CommandReceipts == nil {
		candidate.state.CommandReceipts = map[string]CommandReceipt{}
	}
	candidate.state.CommandReceipts[command.CommandID] = receipt
	previous := s.state
	s.state = candidate.state
	if s.filePath != "" {
		if err = s.saveToFile(); err != nil {
			s.state = previous
			return CommandReceipt{}, err
		}
	}
	return receipt.clone(), nil
}
