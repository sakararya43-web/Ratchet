package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
)

func (s *Service) stageDriftReduction(ctx context.Context, tx pgx.Tx, now time.Time, actor Actor, snapshot *graph.Snapshot, active *policy.Active, drift DriftReceipt, intent domain.Intent, decision domain.Decision, impact graph.Impact) (string, error) {
	if !impact.MonotonicReduction || decision.Outcome != "ALLOW" || decision.Quorum != 0 || intent.Kind != "ROLE_REVOKE" {
		return "", ErrPermission
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+drift.Observation.Connector+":drift-correction:"+drift.Observation.OperationID))
	privateID := uuid.NewSHA1(id, []byte("justification"))
	text := "Revoke the exact authenticated unauthorized role assignment under a proven reduction and the current responder policy."
	private, err := eventstore.SealPrivate(s.key, actor.TenantID, privateID, "workflow-v1", []byte(text))
	if err != nil {
		return "", err
	}
	privateDigest, err := canon.New().Digest(struct {
		Context string `json:"context"`
	}{text})
	if err != nil {
		return "", err
	}
	inputDigest, err := canon.New().Digest(struct {
		Drift  DriftReceipt
		Intent domain.Intent
		Policy string
	}{drift, intent, active.Hash.String()})
	if err != nil {
		return "", err
	}
	var command *PreparedCommand
	m := eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: id.String(), ID: uuid.NewSHA1(id, []byte("stage")), InputDigest: inputDigest, Private: &private}
	m.Additional = func(tx pgx.Tx, receipt eventstore.Receipt) error {
		if command == nil {
			return eventstore.ErrIntegrity
		}
		return s.executions[actor.TenantID].stage(ctx, tx, *command, receipt, now)
	}
	_, err = s.Store.MutateChangeWithin(ctx, tx, now, m, func(tx pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		events, err := domain.Decide(current, domain.Command{Kind: "SUBMIT", At: now, Submission: &domain.Change{ID: id.String(), TenantID: actor.TenantID, Requester: actor.ID, Intent: intent, CorrelationID: drift.Observation.Correlation, PrivateReference: privateID.String(), PrivateDigest: privateDigest, SourceDrift: drift.Observation.DriftID, IncidentReference: drift.IncidentID}})
		if err != nil {
			return nil, err
		}
		c := events[len(events)-1].Change
		envelope := &domain.Envelope{FormatVersion: 2, TenantID: c.TenantID, RequestID: c.ID, Revision: c.Revision + 2, Requester: c.Requester, Intent: c.Intent, GraphVersion: snapshot.Version(), PolicyDigest: active.Hash, RegistryEpoch: active.RegistryEpoch, RegistryDigest: active.RegistryDigest, ExpiresAt: now.Add(s.config.ApprovalLifetime), PrivateReference: c.PrivateReference, PrivateDigest: c.PrivateDigest, ImpactDigest: drift.ReductionDigest}
		digest, err := canon.New().Digest(envelope)
		if err != nil {
			return nil, err
		}
		graphDigest, err := canon.New().Digest(snapshot.Data())
		if err != nil {
			return nil, err
		}
		facts, err := json.Marshal(recordedFacts{Evaluator: evaluatorVersion, Input: factsFor(ctx, snapshot, active, c, impact), GraphDigest: graphDigest})
		if err != nil {
			return nil, err
		}
		assessed, err := domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: decision, Envelope: envelope, Digest: digest, Facts: facts})
		if err != nil {
			return nil, err
		}
		events = append(events, assessed...)
		c = assessed[len(assessed)-1].Change
		cmd, err := s.executions[c.TenantID].prepare(ctx, tx, c, uuid.NewSHA1(id, []byte("execute")).String(), now)
		if err != nil {
			return nil, err
		}
		cmd.Purpose, cmd.SourceDrift, cmd.IncidentReference, cmd.ReductionDigest = "DRIFT_REDUCTION", c.SourceDrift, c.IncidentReference, drift.ReductionDigest
		cmd.Signature = nil
		signatureDigest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", cmd)
		if err != nil {
			return nil, err
		}
		cmd.Signature = ed25519.Sign(s.executions[c.TenantID].private, signatureDigest[:])
		command = &cmd
		dispatched, err := domain.Decide(c, domain.Command{Kind: "DISPATCH", At: now, Digest: c.Digest, ExecutionID: cmd.CommandID})
		if err != nil {
			return nil, err
		}
		events = append(events, dispatched...)
		return events, s.scheduleReconciliation(ctx, tx, c, now)
	})
	return id.String(), err
}
