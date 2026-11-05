package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

const evaluatorVersion = "opa-1.22.0/ratchet-facts-v3"

type recordedFacts struct {
	Evaluator   string       `json:"evaluator"`
	Input       policy.Facts `json:"input"`
	GraphDigest ports.Digest `json:"graph_digest"`
}
type DecisionEvidence struct {
	FormatVersion  int             `json:"format_version"`
	Tenant         string          `json:"tenant_id"`
	Request        string          `json:"request_id"`
	Sequence       int64           `json:"event_sequence"`
	CanonicalEvent json.RawMessage `json:"canonical_event"`
	PreviousHash   ports.Digest    `json:"previous_hash"`
	EventHash      ports.Digest    `json:"event_hash"`
	Graph          graph.Data      `json:"public_graph"`
	Bundle         json.RawMessage `json:"signed_bundle"`
	RegistryProof  json.RawMessage `json:"registry_proof"`
	Root           ports.Digest    `json:"genesis_digest"`
}
type ReplayResult struct {
	Decision      domain.Decision `json:"decision"`
	GraphVersion  int64           `json:"graph_version"`
	PolicyDigest  ports.Digest    `json:"policy_digest"`
	RegistryEpoch int64           `json:"registry_epoch"`
	Evaluator     string          `json:"evaluator"`
}

// DecisionEvidence returns the original assessment even after execution changes
// the current projection's facts. Authorization uses the current signed policy.
func (s *Service) DecisionEvidence(ctx context.Context, actor Actor, request string, revision int64) (DecisionEvidence, error) {
	var evidence DecisionEvidence
	if revision < 0 {
		return evidence, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "investigate", nil)
		if err != nil {
			return err
		}
		events, err := s.Store.StreamWithin(ctx, tx, actor.TenantID, "change:"+request)
		if err != nil {
			return err
		}
		var selected *eventstore.StoredEvent
		for i := range events {
			e := &events[i]
			if e.Type == "ChangeAssessed" && (revision == 0 || e.StreamVersion == revision) {
				selected = e
			}
		}
		if selected == nil {
			return pgx.ErrNoRows
		}
		var content ledger.Content
		if json.Unmarshal(selected.Entry.Canonical, &content) != nil {
			return eventstore.ErrIntegrity
		}
		var payload struct {
			Facts domain.Event `json:"facts"`
		}
		if json.Unmarshal(content.Payload, &payload) != nil {
			return eventstore.ErrIntegrity
		}
		c := payload.Facts.Change
		if c.Envelope == nil {
			return ErrDependency
		}
		if err := tx.QueryRow(ctx, `SELECT raw_bundle,trust_proof FROM ratchet.policy_artifacts WHERE tenant_id=$1 AND digest=$2`, actor.TenantID, c.Envelope.PolicyDigest.Bytes()).Scan(&evidence.Bundle, &evidence.RegistryProof); err != nil {
			return err
		}
		snapshot, err := s.Store.GraphAtWithin(ctx, tx, actor.TenantID, c.Envelope.GraphVersion)
		if err != nil {
			return err
		}
		evidence.FormatVersion = 1
		evidence.Tenant = actor.TenantID
		evidence.Request = request
		evidence.Sequence = selected.Sequence
		evidence.CanonicalEvent = selected.Entry.Canonical
		evidence.EventHash = selected.Entry.Hash
		evidence.PreviousHash = selected.Entry.Previous
		evidence.Graph = snapshot.Data()
		evidence.Root = active.Root
		_, err = ReplayDecision(ctx, evidence, active.Root, selected.Entry.Hash)
		return err
	})
	return evidence, err
}

// ReplayDecision has no database or wall-clock dependencies. Callers pin both
// the independently trusted genesis and an assessment hash from verified history.
// One internally consistent event is not a substitute for a witnessed chain.
func ReplayDecision(ctx context.Context, e DecisionEvidence, root, expectedHash ports.Digest) (ReplayResult, error) {
	var result ReplayResult
	if e.FormatVersion != 1 || root.IsZero() || expectedHash.IsZero() || e.Root != root || e.EventHash != expectedHash {
		return result, eventstore.ErrIntegrity
	}
	content, err := ledger.Verify(canon.New(), ledger.Entry{Canonical: e.CanonicalEvent, Previous: e.PreviousHash, Hash: e.EventHash}, e.Tenant, e.Sequence, e.PreviousHash)
	if err != nil {
		return result, eventstore.ErrIntegrity
	}
	var payload struct {
		Stream   string       `json:"stream_id"`
		Revision int64        `json:"stream_version"`
		Facts    domain.Event `json:"facts"`
	}
	if json.Unmarshal(content.Payload, &payload) != nil || content.EventType != "ChangeAssessed" || payload.Facts.Type != content.EventType || payload.Stream != "change:"+e.Request {
		return result, eventstore.ErrIntegrity
	}
	c := payload.Facts.Change
	if c.ID != e.Request || c.TenantID != e.Tenant || c.Envelope == nil || c.Envelope.FormatVersion != 2 {
		return result, ErrDependency
	}
	if c.State != domain.Assessed || payload.Revision != c.Revision || c.Envelope.TenantID != c.TenantID || c.Envelope.RequestID != c.ID || c.Envelope.Requester != c.Requester || c.Envelope.Revision != c.Revision+1 || c.Envelope.PrivateReference != c.PrivateReference || c.Envelope.PrivateDigest != c.PrivateDigest || !c.UpdatedAt.Before(c.Envelope.ExpiresAt) {
		return result, eventstore.ErrIntegrity
	}
	intent, err := canon.New().Digest(c.Intent)
	if err != nil {
		return result, err
	}
	approvedIntent, err := canon.New().Digest(c.Envelope.Intent)
	if err != nil || approvedIntent != intent {
		return result, eventstore.ErrIntegrity
	}
	a, err := policy.PrepareHistorical(ctx, e.RegistryProof, root, e.Tenant, e.Bundle)
	if err != nil {
		return result, err
	}
	bound, err := canon.New().Digest(c.Envelope)
	if err != nil || bound != c.Digest || c.Envelope.PolicyDigest != a.Hash || c.Envelope.RegistryDigest != a.RegistryDigest || c.Envelope.RegistryEpoch != a.RegistryEpoch {
		return result, eventstore.ErrIntegrity
	}
	snapshot, err := graph.Build(c.Envelope.GraphVersion, e.Graph)
	if err != nil {
		return result, err
	}
	var recorded recordedFacts
	if json.Unmarshal(c.Facts, &recorded) != nil {
		return result, ErrDependency
	}
	switch recorded.Evaluator {
	case evaluatorVersion:
		if recorded.Input.SchemaVersion != 3 {
			return result, ErrDependency
		}
	case "opa-1.22.0/ratchet-facts-v2":
		if recorded.Input.SchemaVersion != 2 {
			return result, ErrDependency
		}
	default:
		return result, ErrDependency
	}
	graphDigest, err := canon.New().Digest(snapshot.Data())
	if err != nil || graphDigest != recorded.GraphDigest {
		return result, eventstore.ErrIntegrity
	}
	impact, _, err := impact(snapshot, c.Intent)
	if err != nil {
		return result, err
	}
	impactDigest, err := canon.New().Digest(impact)
	if err != nil || impactDigest != c.Envelope.ImpactDigest {
		return result, eventstore.ErrIntegrity
	}
	facts := factsFor(ctx, snapshot, a, c, impact)
	if recorded.Input.SchemaVersion == 2 {
		facts.SchemaVersion, facts.Scope = 2, nil
	}
	expectedInput, err := canon.New().Digest(facts)
	if err != nil {
		return result, err
	}
	actualInput, err := canon.New().Digest(recorded.Input)
	if err != nil || actualInput != expectedInput {
		return result, eventstore.ErrIntegrity
	}
	decision, err := a.Decision(ctx, facts)
	if err != nil {
		return result, err
	}
	expectedDecision, err := canon.New().Digest(c.Decision)
	if err != nil {
		return result, err
	}
	actualDecision, err := canon.New().Digest(decision)
	if err != nil || actualDecision != expectedDecision {
		return result, eventstore.ErrIntegrity
	}
	return ReplayResult{Decision: decision, GraphVersion: snapshot.Version(), PolicyDigest: a.Hash, RegistryEpoch: a.RegistryEpoch, Evaluator: recorded.Evaluator}, nil
}
