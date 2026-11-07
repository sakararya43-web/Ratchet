package sim

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	target "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/internal/connector"
)

// ObserveCommand reads the complete target state and its persisted receipt in
// one target snapshot. It does not infer application from desired roles alone.
func (a *Adapter) ObserveCommand(ctx context.Context, cmd *connector.ExecCommand) (*connector.ObservedState, *target.CommandReceipt, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/api/v1/org", nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := a.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, nil, errors.New("target observation unavailable")
	}
	var org target.OrgState
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	if err = decoder.Decode(&org); err != nil {
		return nil, nil, err
	}
	if org.TenantID != a.tenantID || org.TenantID != cmd.TenantID || org.Revision < 1 {
		return nil, nil, errors.New("observation tenant or revision mismatch")
	}
	found := false
	state := &connector.ObservedState{TenantID: org.TenantID, TargetIdentity: cmd.TargetIdentity, ObservedRevision: org.Revision, CurrentRoles: []string{}}
	for _, identity := range org.Identities {
		if identity.ID == cmd.TargetIdentity {
			found = true
			state.IsRestricted = identity.IsDisabled
		}
	}
	if !found {
		return nil, nil, errors.New("observed target identity missing")
	}
	for _, grant := range org.Grants {
		if grant.IdentityID == cmd.TargetIdentity {
			state.CurrentRoles = append(state.CurrentRoles, grant.RoleID)
		}
	}
	for _, session := range org.Sessions {
		if session.IdentityID == cmd.TargetIdentity && !session.IsRevoked {
			state.ActiveSessions = append(state.ActiveSessions, session.SessionID)
		}
	}
	slices.Sort(state.CurrentRoles)
	state.CurrentRoles = slices.Compact(state.CurrentRoles)
	receipt, exists := org.CommandReceipts[cmd.CommandID]
	if !exists {
		return state, nil, nil
	}
	expected := target.TargetCommand{Deadline: cmd.Deadline, CommandID: cmd.CommandID, TenantID: cmd.TenantID, Action: cmd.Action, TargetIdentity: cmd.TargetIdentity, ResourceOrRole: cmd.ResourceOrRole, ExpectedTargetRevision: cmd.ExpectedTargetRevision}
	if receipt.Command != expected {
		return nil, nil, errors.New("target command receipt identity mismatch")
	}
	return state, &receipt, nil
}
