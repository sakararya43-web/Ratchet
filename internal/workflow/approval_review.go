package workflow

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

type ApprovalReview struct {
	Request   string       `json:"request_id"`
	Revision  int64        `json:"revision"`
	Digest    string       `json:"change_digest"`
	Impact    graph.Impact `json:"impact"`
	Approvers []string     `json:"approvers"`
}

// ApprovalReview exposes only an independently reviewable request, never a
// general organization graph. Its impact must match the actual bound envelope.
func (s *Service) ApprovalReview(ctx context.Context, actor Actor, request string) (ApprovalReview, error) {
	var out ApprovalReview
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, request)
		if err != nil {
			return err
		}
		detail, err := s.visibility(ctx, tx, actor, c, snapshot, active)
		if err != nil {
			return err
		}
		if !detail {
			return ErrPermission
		}
		if c.State != domain.AwaitingApproval || c.Envelope == nil || !now.Before(c.Envelope.ExpiresAt) || c.Envelope.GraphVersion != snapshot.Version() || c.Envelope.PolicyDigest != active.Hash || c.Envelope.RegistryEpoch != active.RegistryEpoch || c.Envelope.RegistryDigest != active.RegistryDigest {
			return domain.ErrContextChanged
		}
		_, impact, _, err := s.changeImpactWithin(ctx, tx, snapshot, active, c)
		if err != nil {
			return err
		}
		digest, err := canon.New().Digest(impact)
		if err != nil {
			return err
		}
		if digest != c.Envelope.ImpactDigest {
			return domain.ErrContextChanged
		}
		out = ApprovalReview{Request: c.ID, Revision: c.Revision, Digest: c.Digest.String(), Impact: impact, Approvers: []string{}}
		for _, approval := range c.Approvals {
			out.Approvers = append(out.Approvers, approval.ActorID)
		}
		return nil
	})
	return out, err
}
