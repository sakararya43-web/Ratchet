package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type InlineInput struct {
	Intent          domain.Intent `json:"intent"`
	AdmissionID     string        `json:"admission_id"`
	ObjectDigest    ports.Digest  `json:"object_digest"`
	TargetRevision  string        `json:"target_revision"`
	ApprovedRequest string        `json:"approved_request_id"`
	MinGraphVersion int64         `json:"min_graph_version"`
}

type InlineDecision struct {
	ID                  string          `json:"decision_id"`
	InputDigest         ports.Digest    `json:"input_digest"`
	Actor               Actor           `json:"actor"`
	Input               InlineInput     `json:"input"`
	Decision            domain.Decision `json:"decision"`
	PolicyOutcome       string          `json:"policy_outcome"`
	GraphVersion        int64           `json:"graph_version"`
	PolicyDigest        ports.Digest    `json:"policy_digest"`
	RegistryDigest      ports.Digest    `json:"registry_digest"`
	RegistryEpoch       int64           `json:"registry_epoch"`
	ObjectDigest        ports.Digest    `json:"object_digest"`
	ExecutionAuthorized bool            `json:"execution_authorized"`
	At                  time.Time       `json:"at"`
	ExpiresAt           time.Time       `json:"expires_at"`
}

// DecideInline records a policy refusal/approval requirement or consumes exactly
// one staged, independently approved simulator command. It never submits a new
// change, skips the execution guard or marks a target write as verified.
func (s *Service) DecideInline(ctx context.Context, actor Actor, input InlineInput) (out InlineDecision, err error) {
	admission, err := uuid.Parse(input.AdmissionID)
	if err != nil || admission == uuid.Nil || admission.String() != input.AdmissionID || input.ObjectDigest.IsZero() || input.MinGraphVersion < 0 || input.MinGraphVersion > ledger.MaxSafeInteger || len(input.TargetRevision) > 128 {
		return out, domain.ErrInvalid
	}
	if err := input.Intent.Validate(); err != nil {
		return out, err
	}
	ctx, span := s.observer.Start(ctx, "inline_decision", actor.TenantID, input.AdmissionID)
	defer func() { span.End(err) }()
	if input.ApprovedRequest != "" {
		id, err := uuid.Parse(input.ApprovedRequest)
		if err != nil || id == uuid.Nil || id.String() != input.ApprovedRequest {
			return out, domain.ErrInvalid
		}
	}
	digest, err := canon.New().Digest(struct {
		Actor Actor
		Input InlineInput
	}{actor, input})
	if err != nil {
		return out, err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":inline:"+actor.ID+":"+input.AdmissionID))
	err = s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "simulate", nil)
		if err != nil {
			return err
		}
		stream := "inline:" + id.String()
		prior, err := s.Store.StreamWithin(ctx, tx, actor.TenantID, stream)
		if err != nil {
			return err
		}
		if len(prior) > 0 {
			var content ledger.Content
			var payload struct {
				Facts InlineDecision `json:"facts"`
			}
			if len(prior) != 1 || prior[0].Type != "InlineDecisionRecorded" || json.Unmarshal(prior[0].Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil || payload.Facts.ID != id.String() {
				return eventstore.ErrIntegrity
			}
			out = payload.Facts
			if out.InputDigest != digest {
				return eventstore.ErrIdempotencyConflict
			}
			// Retrying a consumed admission never returns another allow permit.
			if out.ExecutionAuthorized {
				out.ExecutionAuthorized = false
				out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"admission already consumed; reconcile the original command"}}
			}
			return nil
		}
		out = InlineDecision{ID: id.String(), InputDigest: digest, Actor: actor, Input: input, ObjectDigest: input.ObjectDigest, At: now, GraphVersion: snapshot.Version(), PolicyDigest: active.Hash, RegistryDigest: active.RegistryDigest, RegistryEpoch: active.RegistryEpoch}
		if snapshot.Version() < input.MinGraphVersion {
			out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"graph has not reached the requested version"}}
		} else {
			result, delta, err := impact(snapshot, input.Intent)
			if err != nil {
				out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"complete impact context unavailable"}}
			} else {
				out.Decision, err = s.decidePolicy(ctx, actor.TenantID, input.AdmissionID, active, factsFor(ctx, snapshot, active, domain.Change{Requester: actor.ID, Intent: input.Intent}, result))
				if err != nil {
					return err
				}
				out.PolicyOutcome = out.Decision.Outcome
				if input.ApprovedRequest != "" {
					command, err := s.inlineAuthorization(ctx, tx, now, actor, input, snapshot, active, result, delta)
					if err != nil {
						return err
					}
					if command != nil {
						out.Decision = domain.Decision{Outcome: "ALLOW", Reasons: []string{"exact independently approved command consumed for this admission"}}
						out.ExecutionAuthorized, out.ExpiresAt = true, command.Deadline
					} else {
						out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"current exact approved execution binding required"}}
					}
				} else if out.Decision.Outcome == "ALLOW" {
					out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"policy permits reduction; a guarded command is still required for execution"}}
				}
			}
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: id, StreamID: stream, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "InlineDecisionRecorded", Facts: raw}}})
		return err
	})
	return out, err
}

func (s *Service) inlineAuthorization(ctx context.Context, tx pgx.Tx, now time.Time, actor Actor, input InlineInput, snapshot *graph.Snapshot, active *policy.Active, result graph.Impact, delta graph.Delta) (*PreparedCommand, error) {
	c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, input.ApprovedRequest)
	if err != nil {
		return nil, err
	}
	if c.State != domain.Executing || c.Requester != actor.ID || c.ExecutionID != input.AdmissionID || c.Envelope == nil || c.Envelope.GraphVersion != snapshot.Version() || c.Envelope.PolicyDigest != active.Hash || c.Envelope.RegistryDigest != active.RegistryDigest || c.Envelope.RegistryEpoch != active.RegistryEpoch || !now.Before(c.Envelope.ExpiresAt) {
		return nil, nil
	}
	intentDigest, err := canon.New().Digest(input.Intent)
	if err != nil {
		return nil, err
	}
	approvedDigest, err := canon.New().Digest(c.Intent)
	if err != nil || approvedDigest != intentDigest || input.ObjectDigest != intentDigest {
		return nil, nil
	}
	impactDigest, err := canon.New().Digest(result)
	if err != nil || impactDigest != c.Envelope.ImpactDigest {
		return nil, nil
	}
	decision, err := active.Decision(ctx, factsFor(ctx, snapshot, active, c, result))
	if err != nil {
		return nil, err
	}
	if decision.Outcome != c.Decision.Outcome || decision.Quorum != c.Decision.Quorum || !slices.Equal(decision.Groups, c.Decision.Groups) || s.approvals == nil || len(c.Approvals) < max(1, decision.Quorum) {
		return nil, nil
	}
	for _, a := range c.Approvals {
		memberships, err := groups(snapshot, a.ActorID)
		if err != nil || active.Authorize(ctx, policy.Facts{Actor: a.ActorID, Operation: "approve", Groups: memberships, Owners: ownersFor(active, result)}) != nil || eligible(snapshot, c, result, delta, a.ActorID, ownersFor(active, result)) != nil {
			return nil, nil
		}
		verified, err := s.approvals.Verify(ctx, a.Evidence, c.Digest)
		if err != nil || !verified.UserVerified || verified.ActorID != a.ActorID || verified.TenantID != c.TenantID || verified.ChangeDigest != c.Digest || !slices.Equal(verified.CredentialID, a.CredentialID) {
			return nil, nil
		}
	}
	e := s.executions[actor.TenantID]
	if e == nil || !now.Before(e.capability.Expires) {
		return nil, nil
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, actor.TenantID, c.ExecutionID).Scan(&raw); err != nil {
		return nil, err
	}
	var command PreparedCommand
	if json.Unmarshal(raw, &command) != nil {
		return nil, eventstore.ErrIntegrity
	}
	if command.CommandID != input.AdmissionID || command.RequestID != c.ID || command.Tenant != actor.TenantID || command.Connector != e.Connector || command.EnvelopeDigest != c.Digest || command.VerifyOnly || !now.Before(command.Deadline) || input.TargetRevision != strconv.FormatInt(command.ExpectedRevision, 10) {
		return nil, nil
	}
	signature := command.Signature
	command.Signature = nil
	digest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", command)
	if err != nil || !ed25519.Verify(e.private.Public().(ed25519.PublicKey), digest[:], signature) {
		return nil, eventstore.ErrIntegrity
	}
	command.Signature = signature
	return &command, nil
}
