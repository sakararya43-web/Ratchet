package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// CheckAccess verifies whether an identity can perform an action on a target resource.
func (s *Store) CheckAccess(identityID, resourceID, action string) AccessProbeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checkAccessLocked(identityID, resourceID, action)
}

// CheckSessionAccess checks access bound to a specific session.
func (s *Store) CheckSessionAccess(sessionID, resourceID, action string) (AccessProbeResult, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sess *Session
	for i := range s.state.Sessions {
		if s.state.Sessions[i].SessionID == sessionID {
			sess = &s.state.Sessions[i]
			break
		}
	}
	if sess == nil {
		return AccessProbeResult{Allowed: false, Reason: "session not found"}, ""
	}
	if sess.IsRevoked {
		return AccessProbeResult{Allowed: false, Reason: "session is revoked"}, sess.IdentityID
	}

	return s.checkAccessLocked(sess.IdentityID, resourceID, action), sess.IdentityID
}

func (s *Store) checkAccessLocked(identityID, resourceID, action string) AccessProbeResult {
	var targetIdentity *Identity
	for i := range s.state.Identities {
		if s.state.Identities[i].ID == identityID {
			targetIdentity = &s.state.Identities[i]
			break
		}
	}
	if targetIdentity == nil {
		return AccessProbeResult{Allowed: false, Reason: "identity not found"}
	}
	if targetIdentity.IsDisabled {
		return AccessProbeResult{Allowed: false, Reason: "identity is disabled / restricted"}
	}

	roleMap := make(map[string]Role)
	for _, r := range s.state.Roles {
		roleMap[r.ID] = r
	}

	neededPerm := fmt.Sprintf("%s:%s", resourceID, action)
	wildcardPerm := fmt.Sprintf("%s:all", resourceID)

	var rolesUsed []string
	allowed := false

	for _, g := range s.state.Grants {
		if g.IdentityID == identityID {
			if r, ok := roleMap[g.RoleID]; ok {
				for _, p := range r.Permissions {
					if p == neededPerm || p == wildcardPerm || p == "iam:all" {
						allowed = true
						rolesUsed = append(rolesUsed, r.ID)
						break
					}
				}
			}
		}
	}

	if !allowed {
		return AccessProbeResult{
			Allowed: false,
			Reason:  fmt.Sprintf("no active grant permits %q on %q", action, resourceID),
		}
	}

	return AccessProbeResult{
		Allowed:   true,
		Reason:    fmt.Sprintf("authorized via roles: %v", rolesUsed),
		RolesUsed: rolesUsed,
	}
}

// AssignRole grants a role to a target identity.
func (s *Store) AssignRole(actorID, targetIdentity, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	for _, g := range s.state.Grants {
		if g.IdentityID == targetIdentity && g.RoleID == roleID {
			return nil // idempotent
		}
	}

	beforeGrants, _ := json.Marshal(s.getGrantsForIdentity(targetIdentity))

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

	afterGrants, _ := json.Marshal(s.getGrantsForIdentity(targetIdentity))

	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "ASSIGN_ROLE",
		Target:      targetIdentity,
		BeforeState: string(beforeGrants),
		AfterState:  string(afterGrants),
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

	beforeGrants, _ := json.Marshal(s.getGrantsForIdentity(targetIdentity))

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

	afterGrants, _ := json.Marshal(s.getGrantsForIdentity(targetIdentity))

	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "REVOKE_ROLE",
		Target:      targetIdentity,
		BeforeState: string(beforeGrants),
		AfterState:  string(afterGrants),
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
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "TERMINATE_SESSION",
		Target:      sessionID,
		BeforeState: "active",
		AfterState:  "revoked",
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

	for i, sess := range s.state.Sessions {
		if sess.IdentityID == targetIdentity {
			s.state.Sessions[i].IsRevoked = true
		}
	}

	now := time.Now().UTC()
	s.state.Revision++
	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "RESTRICT_ACCOUNT",
		Target:      targetIdentity,
		BeforeState: "enabled",
		AfterState:  "disabled",
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// EnableAccount un-restricts an identity. It NEVER resurrects previously revoked sessions.
func (s *Store) EnableAccount(actorID, targetIdentity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for i, id := range s.state.Identities {
		if id.ID == targetIdentity {
			s.state.Identities[i].IsDisabled = false
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("identity %q not found", targetIdentity)
	}

	now := time.Now().UTC()
	s.state.Revision++
	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "ENABLE_ACCOUNT",
		Target:      targetIdentity,
		BeforeState: "disabled",
		AfterState:  "enabled",
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// IssueSession issues a new active session for an identity.
func (s *Store) IssueSession(actorID, targetIdentity, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for _, id := range s.state.Identities {
		if id.ID == targetIdentity {
			if id.IsDisabled {
				return fmt.Errorf("cannot issue session for disabled identity %q", targetIdentity)
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("identity %q not found", targetIdentity)
	}

	if sessionID == "" {
		sessionID = fmt.Sprintf("session:%s-%d", targetIdentity, time.Now().UnixNano())
	}
	for _, sess := range s.state.Sessions {
		if sess.SessionID == sessionID && !sess.IsRevoked {
			return nil // idempotent
		}
	}

	now := time.Now().UTC()
	s.state.Sessions = append(s.state.Sessions, Session{
		SessionID:  sessionID,
		IdentityID: targetIdentity,
		IsRevoked:  false,
		CreatedAt:  now,
	})
	s.state.Revision++
	s.state.AuditLog = append(s.state.AuditLog, TargetAuditEntry{
		Revision:    s.state.Revision,
		Timestamp:   now,
		ActorID:     actorID,
		Action:      "ISSUE_SESSION",
		Target:      sessionID,
		BeforeState: "none",
		AfterState:  "active",
		Details: map[string]string{
			"identity_id": targetIdentity,
		},
	})

	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// RestoreServicePermission re-grants a role or permission.
func (s *Store) RestoreServicePermission(actorID, targetIdentity, roleOrGrantID string) error {
	return s.AssignRole(actorID, targetIdentity, roleOrGrantID)
}

func (s *Store) getGrantsForIdentity(identityID string) []string {
	var roles []string
	for _, g := range s.state.Grants {
		if g.IdentityID == identityID {
			roles = append(roles, g.RoleID)
		}
	}
	return roles
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
	file, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpFile, s.filePath); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		return directory.Sync()
	}
	return nil
}
