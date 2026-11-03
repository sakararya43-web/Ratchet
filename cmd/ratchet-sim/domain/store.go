package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store provides thread-safe access and persistence for the simulated exchange.
type Store struct {
	mu       sync.RWMutex
	filePath string
	state    *OrgState
}

// NewStore initializes a Store, loading existing state from filePath or initializing with Seed.
func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
	}

	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			if err := s.loadFromFile(); err != nil {
				return nil, fmt.Errorf("failed to load simulator state: %w", err)
			}
			return s, nil
		}
	}

	// Initialize with deterministic seed
	s.state = NewSeedOrgState()
	if filePath != "" {
		if err := s.saveToFile(); err != nil {
			return nil, fmt.Errorf("failed to save initial seed state: %w", err)
		}
	}

	return s, nil
}

// GetState returns a snapshot copy of current OrgState.
func (s *Store) GetState() OrgState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, _ := json.Marshal(s.state)
	var copyState OrgState
	_ = json.Unmarshal(data, &copyState)
	return copyState
}

// ResetToSeed resets the simulator state back to seed and persists it.
func (s *Store) ResetToSeed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = NewSeedOrgState()
	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// AssignRole grants a role to a target identity.
func (s *Store) AssignRole(actorID, targetIdentity, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify identity exists
	foundIdentity := false
	for _, id := range s.state.Identities {
		if id.ID == targetIdentity {
			foundIdentity = true
			break
		}
	}
	if !foundIdentity {
		return fmt.Errorf("identity %q not found", targetIdentity)
	}

	// Verify role exists
	foundRole := false
	for _, r := range s.state.Roles {
		if r.ID == roleID {
			foundRole = true
			break
		}
	}
	if !foundRole {
		return fmt.Errorf("role %q not found", roleID)
	}

	// Check if grant already exists
	for _, g := range s.state.Grants {
		if g.IdentityID == targetIdentity && g.RoleID == roleID {
			return nil // idempotent success
		}
	}

	now := time.Now().UTC()
	s.state.Revision++
	grantID := fmt.Sprintf("grant:%s:%s", targetIdentity, roleID)
	s.state.Grants = append(s.state.Grants, Grant{
		ID:         grantID,
		IdentityID: targetIdentity,
		RoleID:     roleID,
		GrantedAt:  now,
		GrantedBy:  actorID,
	})

	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:  s.state.Revision,
		Timestamp: now,
		ActorID:   actorID,
		Action:    "ASSIGN_ROLE",
		Target:    targetIdentity,
		Details: map[string]string{
			"role_id": roleID,
		},
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// RevokeRole removes a role grant from a target identity.
func (s *Store) RevokeRole(actorID, targetIdentity, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newGrants := make([]Grant, 0, len(s.state.Grants))
	found := false
	for _, g := range s.state.Grants {
		if g.IdentityID == targetIdentity && g.RoleID == roleID {
			found = true
			continue
		}
		newGrants = append(newGrants, g)
	}

	if !found {
		return nil // idempotent
	}

	s.state.Grants = newGrants
	now := time.Now().UTC()
	s.state.Revision++

	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:  s.state.Revision,
		Timestamp: now,
		ActorID:   actorID,
		Action:    "REVOKE_ROLE",
		Target:    targetIdentity,
		Details: map[string]string{
			"role_id": roleID,
		},
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// TerminateSession revokes an active session.
func (s *Store) TerminateSession(actorID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, sess := range s.state.Sessions {
		if sess.SessionID == sessionID {
			s.state.Sessions[i].IsRevoked = true
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("session %q not found", sessionID)
	}

	now := time.Now().UTC()
	s.state.Revision++
	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:  s.state.Revision,
		Timestamp: now,
		ActorID:   actorID,
		Action:    "TERMINATE_SESSION",
		Target:    sessionID,
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// RestrictAccount disables an identity and revokes all its active sessions.
func (s *Store) RestrictAccount(actorID, targetIdentity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, id := range s.state.Identities {
		if id.ID == targetIdentity {
			s.state.Identities[i].IsDisabled = true
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("identity %q not found", targetIdentity)
	}

	// Revoke sessions
	for i, sess := range s.state.Sessions {
		if sess.IdentityID == targetIdentity {
			s.state.Sessions[i].IsRevoked = true
		}
	}

	now := time.Now().UTC()
	s.state.Revision++
	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:  s.state.Revision,
		Timestamp: now,
		ActorID:   actorID,
		Action:    "RESTRICT_ACCOUNT",
		Target:    targetIdentity,
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

func (s *Store) loadFromFile() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var state OrgState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	s.state = &state
	return nil
}

func (s *Store) saveToFile() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, s.filePath)
}
