package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Temporary grant status constants
const (
	GrantStatusActive  = "ACTIVE"
	GrantStatusRevoked = "REVOKED"
	GrantStatusFailed  = "FAILED"
)

// TemporaryGrantRecord tracks a time-bounded grant subject to automated revocation upon expiry.
type TemporaryGrantRecord struct {
	GrantID    string     `json:"grant_id"`
	TenantID   string     `json:"tenant_id"`
	IdentityID string     `json:"identity_id"`
	RoleID     string     `json:"role_id"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Status     string     `json:"status"` // ACTIVE, REVOKED, FAILED
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	FailReason string     `json:"fail_reason,omitempty"`
}

// TemporaryGrantManager schedules and enforces time-bounded grant lifecycles with read-back verification.
type TemporaryGrantManager struct {
	mu       sync.RWMutex
	adapter  TargetAdapter
	filePath string
	grants   map[string]*TemporaryGrantRecord // key: grant_id
}

// NewTemporaryGrantManager creates a TemporaryGrantManager.
func NewTemporaryGrantManager(adapter TargetAdapter, filePath string) (*TemporaryGrantManager, error) {
	tgm := &TemporaryGrantManager{
		adapter:  adapter,
		filePath: filePath,
		grants:   make(map[string]*TemporaryGrantRecord),
	}

	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			if err := tgm.loadFromFile(); err != nil {
				return nil, fmt.Errorf("failed to load temporary grants: %w", err)
			}
		}
	}

	return tgm, nil
}

// ScheduleGrant registers a new active temporary grant.
func (tgm *TemporaryGrantManager) ScheduleGrant(grant *TemporaryGrantRecord) error {
	tgm.mu.Lock()
	defer tgm.mu.Unlock()

	if grant.GrantID == "" || grant.IdentityID == "" || grant.RoleID == "" {
		return fmt.Errorf("grant_id, identity_id, and role_id are required")
	}

	if grant.Status == "" {
		grant.Status = GrantStatusActive
	}
	if grant.GrantedAt.IsZero() {
		grant.GrantedAt = time.Now().UTC()
	}

	tgm.grants[grant.GrantID] = grant

	if tgm.filePath != "" {
		return tgm.saveToFile()
	}
	return nil
}

// CheckAndRevokeExpired inspects all active temporary grants, revokes expired grants, and verifies read-back.
func (tgm *TemporaryGrantManager) CheckAndRevokeExpired(ctx context.Context, now time.Time) ([]*TemporaryGrantRecord, error) {
	tgm.mu.Lock()
	defer tgm.mu.Unlock()

	var processed []*TemporaryGrantRecord

	for _, grant := range tgm.grants {
		if grant.Status != GrantStatusActive {
			continue
		}

		if now.After(grant.ExpiresAt) || now.Equal(grant.ExpiresAt) {
			// Time expired! Dispatch automated reduction command
			cmd := &ExecCommand{
				CommandID:      fmt.Sprintf("sched-revoke-%s-%d", grant.GrantID, now.Unix()),
				TenantID:       grant.TenantID,
				RequestID:      grant.GrantID,
				Action:         "REVOKE_ROLE",
				TargetIdentity: grant.IdentityID,
				ResourceOrRole: grant.RoleID,
				IsReduction:    true,
			}

			execRes, err := tgm.adapter.Execute(ctx, cmd)
			if err != nil || (execRes != nil && !execRes.Success) {
				errMsg := "revocation execution failed"
				if err != nil {
					errMsg = err.Error()
				} else if execRes != nil && execRes.ErrorMessage != "" {
					errMsg = execRes.ErrorMessage
				}
				grant.Status = GrantStatusFailed
				grant.FailReason = errMsg
				processed = append(processed, grant)
				continue
			}

			// Independently verify read-back
			_, err = tgm.adapter.Verify(ctx, cmd)
			if err != nil {
				grant.Status = GrantStatusFailed
				grant.FailReason = fmt.Sprintf("read-back verification mismatch: %v", err)
				processed = append(processed, grant)
				continue
			}

			// Successfully revoked & verified!
			revTime := now.UTC()
			grant.Status = GrantStatusRevoked
			grant.RevokedAt = &revTime
			grant.FailReason = ""
			processed = append(processed, grant)
		}
	}

	if len(processed) > 0 && tgm.filePath != "" {
		_ = tgm.saveToFile()
	}

	return processed, nil
}

// ListGrants returns all registered temporary grants.
func (tgm *TemporaryGrantManager) ListGrants() []*TemporaryGrantRecord {
	tgm.mu.RLock()
	defer tgm.mu.RUnlock()

	list := make([]*TemporaryGrantRecord, 0, len(tgm.grants))
	for _, g := range tgm.grants {
		list = append(list, g)
	}
	return list
}

func (tgm *TemporaryGrantManager) loadFromFile() error {
	data, err := os.ReadFile(tgm.filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &tgm.grants)
}

func (tgm *TemporaryGrantManager) saveToFile() error {
	data, err := json.MarshalIndent(tgm.grants, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(tgm.filePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	tmp := tgm.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, tgm.filePath)
}
