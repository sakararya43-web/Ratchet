package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type ContainmentBody struct {
	Domain         string             `json:"domain"`
	FormatVersion  int                `json:"format_version"`
	ID             string             `json:"plan_id"`
	Tenant         string             `json:"tenant_id"`
	Requester      string             `json:"requester"`
	CorrelationID  string             `json:"correlation_id"`
	PolicyDigest   ports.Digest       `json:"policy_digest"`
	RegistryDigest ports.Digest       `json:"registry_digest"`
	RegistryEpoch  int64              `json:"registry_epoch"`
	CreatedAt      time.Time          `json:"created_at"`
	ExpiresAt      time.Time          `json:"expires_at"`
	Catalog        []graph.Revocation `json:"catalog"`
	Plan           graph.Containment  `json:"plan"`
	RoutesCount    int                `json:"captured_tier0_routes"`
	RoutesComplete bool               `json:"routes_count_complete"`
}
type ContainmentProposal struct {
	Body   ContainmentBody `json:"body"`
	Digest ports.Digest    `json:"digest"`
}
type PlanInput struct {
	CommandID               uuid.UUID
	CorrelationID, Identity string
	MinGraphVersion         int64
	Costs                   map[string]int64
}

func (s *Service) PlanContainment(ctx context.Context, actor Actor, input PlanInput) (ContainmentProposal, error) {
	var proposal ContainmentProposal
	if input.CommandID == uuid.Nil || input.Identity == "" || input.MinGraphVersion < 0 || input.MinGraphVersion > 1<<53-1 {
		return proposal, domain.ErrInvalid
	}
	if id, err := uuid.Parse(input.CorrelationID); err != nil || id == uuid.Nil {
		return proposal, domain.ErrInvalid
	}
	if err := graph.ValidateRevocationCosts(input.Costs); err != nil {
		return proposal, err
	}
	inputDigest, err := canon.New().Digest(struct {
		Actor Actor
		Input PlanInput
	}{actor, input})
	if err != nil {
		return proposal, err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":containment:"+input.CommandID.String()))
	err = s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "containment_plan", nil)
		if err != nil {
			return err
		}
		var prior, raw, digest []byte
		err = tx.QueryRow(ctx, `SELECT input_digest,document,plan_digest FROM ratchet.containment_plans WHERE tenant_id=$1 AND plan_id=$2`, actor.TenantID, id).Scan(&prior, &raw, &digest)
		if err == nil {
			if string(prior) != string(inputDigest[:]) {
				return eventstore.ErrIdempotencyConflict
			}
			if json.Unmarshal(raw, &proposal) != nil {
				return eventstore.ErrIntegrity
			}
			expected, err := canon.New().Digest(proposal.Body)
			if err != nil || expected != proposal.Digest || string(expected[:]) != string(digest) {
				return eventstore.ErrIntegrity
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if snapshot.Version() < input.MinGraphVersion {
			return graph.ErrUnavailable
		}
		catalog, err := snapshot.RevocationCatalog([]string{input.Identity}, input.Costs)
		if err != nil {
			return err
		}
		plan, err := snapshot.PlanContainment(ctx, []string{input.Identity}, catalog, 2048)
		if err != nil {
			return err
		}
		paths, err := snapshot.PathsTo(input.Identity, 1000, 1_000_000)
		if err != nil {
			return err
		}
		proposal.Body = ContainmentBody{Domain: "RATCHET_CONTAINMENT_PLAN_V1", FormatVersion: 1, ID: id.String(), Tenant: actor.TenantID, Requester: actor.ID, CorrelationID: input.CorrelationID, PolicyDigest: active.Hash, RegistryDigest: active.RegistryDigest, RegistryEpoch: active.RegistryEpoch, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), Catalog: catalog, Plan: plan, RoutesCount: len(paths.Routes), RoutesComplete: !paths.Truncated}
		proposal.Digest, err = canon.New().Digest(proposal.Body)
		if err != nil {
			return err
		}
		raw, err = json.Marshal(proposal)
		if err != nil {
			return err
		}
		receipt, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: input.CommandID, StreamID: "containment:" + id.String(), ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "ContainmentPlanned", Facts: raw}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.containment_plans(tenant_id,plan_id,input_digest,plan_digest,document,event_position) VALUES($1,$2,$3,$4,$5,$6)`, actor.TenantID, id, inputDigest.Bytes(), proposal.Digest.Bytes(), raw, receipt.LastSequence)
		return err
	})
	return proposal, err
}
