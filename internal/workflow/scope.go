package workflow

import (
	"slices"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
)

// scopeReview compares effective role powers with explicit requested resources
// and actions. It does not invent a business need or score justification text.
func scopeReview(intent domain.Intent, impact graph.Impact) *policy.ScopeReview {
	if !intent.Emergency && intent.DurationSeconds == 0 && len(intent.Resources) == 0 && len(intent.Permissions) == 0 {
		return nil
	}
	r := &policy.ScopeReview{Resources: []string{}, Permissions: []string{}}
	if intent.Kind != "ROLE_ASSIGN" || len(intent.Resources) == 0 || len(intent.Permissions) == 0 {
		return r
	}
	r.Complete = true
	for _, affected := range impact.Affected {
		if len(affected.NewControlled) > 0 || (affected.IdentityID != intent.Target && len(affected.NewPowers) > 0) {
			r.ControlsOtherIdentities = true
		}
		for _, power := range affected.NewPowers {
			if !slices.Contains(intent.Resources, power.NodeID) {
				r.Resources = append(r.Resources, power.NodeID)
			}
			if !slices.Contains(intent.Permissions, power.Action) {
				r.Permissions = append(r.Permissions, power.Action)
			}
		}
	}
	slices.Sort(r.Resources)
	r.Resources = slices.Compact(r.Resources)
	slices.Sort(r.Permissions)
	r.Permissions = slices.Compact(r.Permissions)
	r.OverBroad = len(r.Resources) > 0 || len(r.Permissions) > 0 || r.ControlsOtherIdentities
	return r
}
