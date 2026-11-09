package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

type ExecuteContainmentInput struct {
	CommandID       uuid.UUID
	CorrelationID   string
	PlanID          string
	PlanDigest      ports.Digest
	AssertionJSON   string
	ResponderID     string
	MinGraphVersion int64
}

type ContainmentExecutionResult struct {
	Executed          bool
	Pending           bool
	IncidentID        string
	VerifiedLatencyMs int64
	ExecutionResults  []ContainmentActionResult
}

type ContainmentActionResult struct {
	ActionID            string
	ActionType          string
	TargetIdentity      string
	Success             bool
	ErrorMessage        string
	AppliedAt           time.Time
	TargetRevisionAfter int64
	ReadBackVerified    bool
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

func (s *Service) ExecuteContainment(ctx context.Context, actor Actor, input ExecuteContainmentInput) (ContainmentExecutionResult, error) {
	var result ContainmentExecutionResult
	if input.CommandID == uuid.Nil || input.PlanID == "" || input.PlanDigest.IsZero() || input.ResponderID == "" || input.AssertionJSON == "" || input.MinGraphVersion < 0 || input.MinGraphVersion > 1<<53-1 {
		return result, domain.ErrInvalid
	}
	if _, err := uuid.Parse(input.PlanID); err != nil {
		return result, domain.ErrInvalid
	}
	if id, err := uuid.Parse(input.CorrelationID); err != nil || id == uuid.Nil {
		return result, domain.ErrInvalid
	}
	if actor.ID != input.ResponderID {
		return result, ErrPermission
	}

	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, active, err := s.context(ctx, tx, actor, "containment_execute", nil)
		if err != nil {
			return err
		}
		if snapshot.Version() < input.MinGraphVersion {
			return graph.ErrUnavailable
		}

		proposal, err := s.containmentProposal(ctx, tx, actor.TenantID, input.PlanID)
		if err != nil {
			return err
		}
		if proposal.Digest != input.PlanDigest {
			return domain.ErrContextChanged
		}
		if now.After(proposal.Body.ExpiresAt) {
			return domain.ErrInvalid
		}
		if proposal.Body.PolicyDigest != active.Hash || proposal.Body.RegistryDigest != active.RegistryDigest || proposal.Body.RegistryEpoch != active.RegistryEpoch {
			return domain.ErrContextChanged
		}
		if snapshot.Version() < proposal.Body.Plan.GraphVersion {
			return graph.ErrUnavailable
		}

		cv, ok := s.approvals.(ports.ContainmentVerifier)
		if !ok {
			return ErrDependency
		}
		var submission ports.ApprovalSubmission
		if err := json.Unmarshal([]byte(input.AssertionJSON), &submission); err != nil {
			return domain.ErrInvalid
		}
		submission.TenantID = actor.TenantID
		submission.ActorID = actor.ID
		verified, err := cv.VerifyContainment(ctx, submission, proposal.Digest)
		if err != nil {
			return ErrPermission
		}
		if verified.ActorID != actor.ID || verified.TenantID != actor.TenantID || !verified.UserVerified || verified.ChangeDigest != proposal.Digest {
			return ErrPermission
		}

		reduced, _, err := snapshot.ApplyRevocations(proposal.Body.Plan.Actions)
		if err != nil {
			return err
		}
		residualPaths, err := reduced.PathsTo(proposal.Body.Plan.Origins[0], 1000, 1_000_000)
		if err != nil {
			return err
		}
		if len(residualPaths.Routes) > 0 {
			return graph.ErrNoContainment
		}

		incidentID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":incident:"+proposal.Body.ID)).String()
		incidentStreamID := "incident:" + incidentID

		_, incErr := s.incidentWithin(ctx, tx, actor.TenantID, incidentID, 0)
		if incErr != nil {
			if !errors.Is(incErr, pgx.ErrNoRows) {
				return incErr
			}
			openFingerprint, err := canon.New().Digest(struct {
				PlanID string
				Tenant string
			}{proposal.Body.ID, actor.TenantID})
			if err != nil {
				return err
			}
			openIncident := Incident{
				ID:              incidentID,
				Tenant:          actor.TenantID,
				CorrelationID:   input.CorrelationID,
				Identity:        proposal.Body.Plan.Origins[0],
				PlanID:          proposal.Body.ID,
				PlanDigest:      proposal.Digest,
				Status:          "OPEN",
				OpenedAt:        now,
				Revision:        1,
				OpenFingerprint: openFingerprint,
			}
			openRaw, err := json.Marshal(openIncident)
			if err != nil {
				return err
			}
			if _, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{
				TenantID:       actor.TenantID,
				ID:             uuid.NewSHA1(input.CommandID, []byte("incident-open")),
				StreamID:       incidentStreamID,
				ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)),
				Events:         []eventstore.Event{{Type: "IncidentOpened", Facts: openRaw}},
			}); err != nil {
				return err
			}
		}

		execution := s.executions[actor.TenantID]
		if execution == nil {
			return ErrDependency
		}

		var connectorRevision int64
		var sourceRaw []byte
		var quarantine bool
		if err := tx.QueryRow(ctx, `SELECT source_revision,public_graph,needs_resync FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id=$2`, actor.TenantID, execution.Connector).Scan(&connectorRevision, &sourceRaw, &quarantine); err != nil {
			return err
		}
		if quarantine {
			return ErrDependency
		}

		// Durable idempotency: exact replay returns existing dispatch, conflicting attempt fails
		priorEvents, err := s.Store.StreamWithin(ctx, tx, actor.TenantID, "containment:"+proposal.Body.ID)
		if err == nil {
			for _, ev := range priorEvents {
				if ev.Type == "ContainmentDispatched" {
					var content struct {
						Payload json.RawMessage `json:"payload"`
					}
					var payload struct {
						Facts json.RawMessage `json:"facts"`
					}
					if json.Unmarshal(ev.Entry.Canonical, &content) == nil && json.Unmarshal(content.Payload, &payload) == nil {
						var priorCmd PreparedCommand
						if json.Unmarshal(payload.Facts, &priorCmd) == nil {
							if len(priorCmd.Approvals) > 0 && priorCmd.Approvals[0].ActorID == actor.ID && priorCmd.IncidentReference == incidentID {
								result.Executed = false
								result.Pending = true
								result.IncidentID = incidentID
								result.VerifiedLatencyMs = 0
								return nil
							}
							return eventstore.ErrIdempotencyConflict
						}
					}
				}
			}
		}

		currentSeqRevision := connectorRevision
		for i, action := range proposal.Body.Plan.Actions {
			actionCmdID := uuid.NewSHA1(input.CommandID, []byte(fmt.Sprintf("contain-action-%d", i))).String()
			actionReqID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(proposal.Body.ID+fmt.Sprintf(":%d", i))).String()

			actionIntent := domain.Intent{
				Kind:       action.Kind,
				Target:     action.Target,
				Access:     action.Access,
				IncidentID: incidentID,
			}
			env := &domain.Envelope{
				FormatVersion:    2,
				TenantID:         actor.TenantID,
				RequestID:        actionReqID,
				Revision:         1,
				Requester:        actor.ID,
				Intent:           actionIntent,
				GraphVersion:     snapshot.Version(),
				PolicyDigest:     active.Hash,
				RegistryEpoch:    active.RegistryEpoch,
				RegistryDigest:   active.RegistryDigest,
				ExpiresAt:        proposal.Body.ExpiresAt,
				PrivateReference: uuid.NewSHA1(input.CommandID, []byte(fmt.Sprintf("priv-%d", i))).String(),
				PrivateDigest:    proposal.Digest,
				ImpactDigest:     proposal.Digest,
			}
			envDigest, err := canon.New().Digest(env)
			if err != nil {
				return err
			}

			roles := []string{}
			_, out, _ := snapshot.IncidentEdges(action.Target)
			for _, e := range out {
				if e.Kind == "ASSIGNED" {
					roles = append(roles, e.Target)
				}
			}
			slices.Sort(roles)
			beforeRoles := append([]string(nil), roles...)
			expectedRoles := append([]string(nil), roles...)
			if action.Kind == "ROLE_REVOKE" {
				expectedRoles = slices.DeleteFunc(expectedRoles, func(r string) bool { return r == action.Access })
			}

			actionExpectedRevision := currentSeqRevision
			currentSeqRevision++

			prepCmd := PreparedCommand{
				SchemaVersion:     1,
				Tenant:            actor.TenantID,
				Connector:         execution.Connector,
				CommandID:         actionCmdID,
				RequestID:         actionReqID,
				CorrelationID:     input.CorrelationID,
				MessageID:         actionCmdID,
				ExpectedRevision:  actionExpectedRevision,
				Envelope:          env,
				EnvelopeDigest:    envDigest,
				BeforeRoles:       beforeRoles,
				ExpectedRoles:     expectedRoles,
				Approvals: []domain.Approval{
					{
						ActorID:      actor.ID,
						CredentialID: verified.CredentialID,
						Digest:       proposal.Digest,
						VerifiedAt:   verified.VerifiedAt,
						Evidence:     submission,
					},
				},
				Deadline:          proposal.Body.ExpiresAt,
				DispatchedAt:      now,
				Purpose:           "CONTAINMENT",
				IncidentReference: incidentID,
				ReductionDigest:   proposal.Digest,
			}
			prepCmd.Signature = nil
			sigDigest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", prepCmd)
			if err != nil {
				return err
			}
			prepCmd.Signature = ed25519.Sign(execution.private, sigDigest[:])

			rawCmd, err := json.Marshal(prepCmd)
			if err != nil {
				return err
			}

			rolesJSON, err := json.Marshal(expectedRoles)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ratchet.execution_attempts(tenant_id,command_id,request_id,connector_id,source_revision,envelope_digest,expected_roles,deadline,command_payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
				actor.TenantID, actionCmdID, actionReqID, execution.Connector, actionExpectedRevision, envDigest.Bytes(), rolesJSON, prepCmd.Deadline, rawCmd); err != nil {
				return err
			}

			receipt, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{
				TenantID:       actor.TenantID,
				ID:             uuid.NewSHA1(input.CommandID, []byte(fmt.Sprintf("event-%d", i))),
				StreamID:       "containment:" + proposal.Body.ID,
				ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)),
				Events:         []eventstore.Event{{Type: "ContainmentDispatched", Facts: rawCmd}},
			})
			if err != nil {
				return err
			}

			_, err = tx.Exec(ctx, `INSERT INTO ratchet.outbox(tenant_id,event_id,sequence,subject,payload,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
				actor.TenantID, actionCmdID, receipt.LastSequence, "ratchet."+actor.TenantID+".contain."+execution.Connector, rawCmd, now)
			if err != nil {
				return err
			}

			result.ExecutionResults = append(result.ExecutionResults, ContainmentActionResult{
				ActionID:            actionCmdID,
				ActionType:          action.Kind,
				TargetIdentity:      action.Target,
				Success:             false,
				AppliedAt:           time.Time{},
				TargetRevisionAfter: actionExpectedRevision,
				ReadBackVerified:    false,
			})
		}

		result.Executed = false
		result.Pending = true
		result.IncidentID = incidentID
		result.VerifiedLatencyMs = 0
		return nil
	})

	return result, err
}

