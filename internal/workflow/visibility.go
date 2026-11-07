package workflow

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
)

func (s *Service) visibility(ctx context.Context, tx pgx.Tx, actor Actor, c domain.Change, snapshot *graph.Snapshot, active *policy.Active) (bool, error) {
	if c.TenantID != actor.TenantID {
		return false, ErrPermission
	}
	memberships, err := groups(snapshot, actor.ID)
	if err != nil {
		return false, err
	}
	if active.Authorize(ctx, policy.Facts{Actor: actor.ID, Operation: "investigate", Groups: memberships}) == nil {
		return true, nil
	}
	if c.Requester == actor.ID {
		return false, nil
	}
	snapshot, result, delta, err := s.changeImpactWithin(ctx, tx, snapshot, active, c)
	if err != nil {
		return false, ErrPermission
	}
	owners := ownersFor(active, result)
	if active.Authorize(ctx, policy.Facts{Actor: actor.ID, Operation: "approve", Groups: memberships, Owners: owners}) != nil {
		return false, ErrPermission
	}
	review := c
	review.Decision.Groups = []string{"resource-owner", "role:security-lead"}
	if eligible(snapshot, review, result, delta, actor.ID, owners) != nil {
		return false, ErrPermission
	}
	return true, nil
}

// ResponseDetail is rechecked at the API boundary for every response, including
// mutation receipts. A requester receives safe status; independent reviewers
// and explicitly authorized investigators can inspect the evidence.
func (s *Service) ResponseDetail(ctx context.Context, actor Actor, c domain.Change) (bool, error) {
	var detail bool
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		detail, err = s.visibility(ctx, tx, actor, c, snapshot, active)
		return err
	})
	return detail, err
}
