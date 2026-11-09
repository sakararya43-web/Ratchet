package workflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

// Capability is signed by the configured connector, not asserted by a runtime
// flag. An old connector cannot accidentally receive an authorized legacy write.
type Capability struct {
	Tenant              string    `json:"tenant_id"`
	Connector           string    `json:"connector_id"`
	Protocol            string    `json:"protocol"`
	Expires             time.Time `json:"expires_at"`
	BoundCommands       bool      `json:"bound_commands"`
	AtomicPreconditions bool      `json:"atomic_preconditions"`
	DurableDedup        bool      `json:"durable_dedup"`
	IndependentReadBack bool      `json:"independent_read_back"`
	ScheduledRevocation bool      `json:"scheduled_revocation,omitempty"`
	ProvenReductions    bool      `json:"proven_reductions,omitempty"`
	NativeRBAC          bool      `json:"native_rbac,omitempty"`
	Signature           []byte    `json:"signature"`
}

func signingDigest(domainName string, value any) (ports.Digest, error) {
	return canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{domainName, value})
}

type Execution struct {
	Tenant, Connector string
	public            ed25519.PublicKey
	private           ed25519.PrivateKey
	capability        Capability
}

func NewExecution(tenant, connector string, public ed25519.PublicKey, private ed25519.PrivateKey, capability Capability) (*Execution, error) {
	if len(public) != 32 || len(private) != 64 || tenant == "" || connector == "" || connector == "results" || capability.Tenant != tenant || capability.Connector != connector || capability.Protocol != "RATCHET_EXEC_V1" || !capability.BoundCommands || !capability.AtomicPreconditions || !capability.DurableDedup || !capability.IndependentReadBack {
		return nil, ErrDependency
	}
	signature := capability.Signature
	capability.Signature = nil
	digest, err := signingDigest("RATCHET_EXEC_CAPABILITY_V1", capability)
	if err != nil || !ed25519.Verify(public, digest[:], signature) {
		return nil, ErrDependency
	}
	return &Execution{tenant, connector, append(ed25519.PublicKey(nil), public...), append(ed25519.PrivateKey(nil), private...), capability}, nil
}

type PreparedCommand struct {
	MessageID         string                `json:"message_id"`
	VerifyOnly        bool                  `json:"verify_only"`
	SchemaVersion     int                   `json:"schema_version"`
	Tenant            string                `json:"tenant_id"`
	Connector         string                `json:"connector_id"`
	CommandID         string                `json:"command_id"`
	RequestID         string                `json:"request_id"`
	CorrelationID     string                `json:"correlation_id"`
	ExpectedRevision  int64                 `json:"expected_target_revision"`
	ExpectedRoles     []string              `json:"expected_roles"`
	BeforeRoles       []string              `json:"before_roles"`
	Envelope          *domain.Envelope      `json:"approved_envelope"`
	EnvelopeDigest    ports.Digest          `json:"approved_envelope_digest"`
	Approvals         []domain.Approval     `json:"approvals"`
	Deadline          time.Time             `json:"deadline"`
	DispatchedAt      time.Time             `json:"dispatched_at"`
	Signature         []byte                `json:"signature"`
	Purpose           string                `json:"purpose,omitempty"`
	GrantExpiresAt    time.Time             `json:"grant_expires_at,omitempty"`
	OriginalCommandID string                `json:"original_command_id,omitempty"`
	TraceParent       string                `json:"traceparent,omitempty"`
	SourceDrift       string                `json:"source_drift_id,omitempty"`
	IncidentReference string                `json:"incident_reference,omitempty"`
	ReductionDigest   ports.Digest          `json:"reduction_digest,omitempty"`
	Kubernetes        *NativeCommandBinding `json:"kubernetes,omitempty"`
}

func (e *Execution) prepare(ctx context.Context, tx pgx.Tx, c domain.Change, id string, now time.Time) (PreparedCommand, error) {
	var cmd PreparedCommand
	if e == nil || e.Tenant != c.TenantID || !now.Before(e.capability.Expires) || e.capability.Expires.After(now.Add(24*time.Hour)) {
		return cmd, ErrDependency
	}
	switch c.Intent.Kind {
	case "ROLE_ASSIGN", "ROLE_REVOKE",
		"RESTRICT_ACCOUNT", "ENABLE_ACCOUNT",
		"REMOVE_SERVICE_PERMISSION", "RESTORE_SERVICE_PERMISSION",
		"TERMINATE_SESSION", "ISSUE_SESSION":
	default:
		return cmd, domain.ErrInvalid
	}
	if c.Intent.DurationSeconds > 0 && (!e.capability.ScheduledRevocation || c.Intent.Kind != "ROLE_ASSIGN") {
		return cmd, ErrDependency
	}
	var revision int64
	var raw []byte
	var quarantine bool
	if err := tx.QueryRow(ctx, `SELECT source_revision,public_graph,needs_resync FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id=$2`, c.TenantID, e.Connector).Scan(&revision, &raw, &quarantine); err != nil {
		return cmd, err
	}
	if quarantine {
		return cmd, ErrDependency
	}
	var source struct {
		Nodes []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"nodes"`
		Edges []struct{ Source, Target, Kind string } `json:"edges"`
	}
	if err := json.Unmarshal(raw, &source); err != nil {
		return cmd, err
	}
	exists := false
	roleExists := false
	isRoleOp := c.Intent.Kind == "ROLE_ASSIGN" || c.Intent.Kind == "ROLE_REVOKE"
	for _, node := range source.Nodes {
		exists = exists || node.ID == c.Intent.Target
		roleExists = roleExists || (node.ID == c.Intent.Access && node.Type == "Role")
	}
	if !exists || (isRoleOp && !roleExists) {
		return cmd, ErrDependency
	}
	roles := []string{}
	for _, edge := range source.Edges {
		if edge.Source == c.Intent.Target && edge.Kind == "ASSIGNED" {
			roles = append(roles, edge.Target)
		}
	}
	slices.Sort(roles)
	roles = slices.Compact(roles)
	beforeRoles := slices.Clone(roles)
	switch c.Intent.Kind {
	case "ROLE_ASSIGN":
		if c.Intent.DurationSeconds > 0 && slices.Contains(roles, c.Intent.Access) {
			// An existing permanent grant cannot silently become timer-owned.
			return cmd, domain.ErrInvalid
		}
		if !slices.Contains(roles, c.Intent.Access) {
			roles = append(roles, c.Intent.Access)
		}
	case "ROLE_REVOKE":
		roles = slices.DeleteFunc(roles, func(role string) bool { return role == c.Intent.Access })
	case "RESTORE_SERVICE_PERMISSION":
		if roleExists && !slices.Contains(roles, c.Intent.Access) {
			roles = append(roles, c.Intent.Access)
		}
	case "REMOVE_SERVICE_PERMISSION":
		if roleExists {
			roles = slices.DeleteFunc(roles, func(role string) bool { return role == c.Intent.Access })
		}
	case "ENABLE_ACCOUNT", "RESTRICT_ACCOUNT", "ISSUE_SESSION", "TERMINATE_SESSION":
		// Target identity/session state mutated on connector; role assignments unchanged.
	}
	slices.Sort(roles)
	roles = slices.Compact(roles)
	cmd = PreparedCommand{SchemaVersion: 1, Tenant: c.TenantID, Connector: e.Connector, CommandID: id, RequestID: c.ID, ExpectedRevision: revision, ExpectedRoles: roles, Envelope: c.Envelope, EnvelopeDigest: c.Digest, Approvals: c.Approvals, Deadline: c.Envelope.ExpiresAt}
	cmd.MessageID = id
	cmd.CorrelationID = c.CorrelationID
	if cmd.CorrelationID == "" {
		cmd.CorrelationID = c.ID
	}
	cmd.DispatchedAt = now
	cmd.BeforeRoles = beforeRoles
	cmd.TraceParent = telemetry.Parent(ctx)
	if c.Intent.IncidentID != "" {
		cmd.Purpose = "RESTORE_ACCESS"
		cmd.IncidentReference = c.Intent.IncidentID
	} else if c.Intent.DurationSeconds > 0 {
		cmd.GrantExpiresAt = now.Add(time.Duration(c.Intent.DurationSeconds) * time.Second)
		cmd.Purpose = "TEMPORARY_GRANT"
		if cmd.GrantExpiresAt.Before(cmd.Deadline) {
			cmd.Deadline = cmd.GrantExpiresAt
		}
	}
	digest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", cmd)
	if err != nil {
		return cmd, err
	}
	cmd.Signature = ed25519.Sign(e.private, digest[:])
	return cmd, nil
}
func (e *Execution) stage(ctx context.Context, tx pgx.Tx, cmd PreparedCommand, receipt eventstore.Receipt, now time.Time) error {
	raw, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return domain.ErrInvalid
	}
	roles, err := json.Marshal(cmd.ExpectedRoles)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ratchet.execution_attempts(tenant_id,command_id,request_id,connector_id,source_revision,envelope_digest,expected_roles,deadline,command_payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, cmd.Tenant, cmd.CommandID, cmd.RequestID, cmd.Connector, cmd.ExpectedRevision, cmd.EnvelopeDigest.Bytes(), roles, cmd.Deadline, raw); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ratchet.outbox(tenant_id,event_id,sequence,subject,payload,created_at) VALUES($1,$2,$3,$4,$5,$6)`, cmd.Tenant, cmd.CommandID, receipt.LastSequence, "ratchet."+cmd.Tenant+".exec."+cmd.Connector, raw, now)
	return err
}

type ExecutionResult struct {
	SchemaVersion     int                `json:"schema_version"`
	Tenant            string             `json:"tenant_id"`
	Connector         string             `json:"connector_id"`
	MessageID         string             `json:"message_id"`
	CommandID         string             `json:"command_id"`
	RequestID         string             `json:"request_id"`
	CorrelationID     string             `json:"correlation_id"`
	EnvelopeDigest    ports.Digest       `json:"approved_envelope_digest"`
	Success           bool               `json:"success"`
	ReadBackVerified  bool               `json:"read_back_verified"`
	ObservedTenant    string             `json:"observed_tenant_id"`
	ObservedTarget    string             `json:"observed_target"`
	ObservedRoles     []string           `json:"observed_roles"`
	ObservedRevision  int64              `json:"observed_revision"`
	ObservedAt        time.Time          `json:"observed_at"`
	AppliedAt         time.Time          `json:"applied_at"`
	ObservationDigest ports.Digest       `json:"observation_digest"`
	Signature         []byte             `json:"signature"`
	Kubernetes        *NativeObservation `json:"kubernetes,omitempty"`
}

func (s *Service) RecordExecutionResult(ctx context.Context, tenant string, raw []byte) (err error) {
	if len(raw) > 1<<20 {
		return domain.ErrInvalid
	}
	var r ExecutionResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return domain.ErrInvalid
	}
	if r.Kubernetes != nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF {
			return domain.ErrInvalid
		}
	}
	e := s.executions[tenant]
	if e == nil || r.SchemaVersion != 1 || r.Tenant != tenant || r.Connector != e.Connector {
		return ErrPermission
	}
	signature := r.Signature
	r.Signature = nil
	digest, err := signingDigest("RATCHET_EXEC_RESULT_V1", r)
	if err != nil || !ed25519.Verify(e.public, digest[:], signature) {
		return ErrPermission
	}
	messageID, err := uuid.Parse(r.MessageID)
	if err != nil {
		return domain.ErrInvalid
	}
	ctx, resultSpan := s.observer.Start(ctx, "connector_result", tenant, r.CorrelationID)
	defer func() { resultSpan.End(err) }()
	ctx, verificationSpan := s.observer.Start(ctx, "verification", tenant, r.CorrelationID)
	defer func() { verificationSpan.End(err) }()
	var commandRaw []byte
	var isContainment bool
	var containmentCmd PreparedCommand
	_ = s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error {
		if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, tenant, r.CommandID).Scan(&commandRaw); err == nil {
			if json.Unmarshal(commandRaw, &containmentCmd) == nil && containmentCmd.Purpose == "CONTAINMENT" {
				isContainment = true
			}
		}
		return nil
	})
	if isContainment {
		return s.recordContainmentResult(ctx, tenant, r, containmentCmd)
	}
	request, err := s.Store.ReadChange(ctx, tenant, r.RequestID)
	if err != nil {
		return err
	}
	r.Signature = signature
	mutation := eventstore.ChangeMutation{TenantID: tenant, ActorID: "connector:" + e.Connector, RequestID: r.RequestID, ID: messageID, ExpectedRevision: request.Revision, InputDigest: digest}
	if r.Kubernetes != nil {
		private, err := eventstore.SealPrivate(s.key, tenant, uuid.NewSHA1(messageID, []byte("native-read-back")), "native-read-back-v1", raw)
		if err != nil {
			return err
		}
		mutation.Private = &private
	}
	if request.SourceDrift != "" {
		mutation.Additional = func(tx pgx.Tx, _ eventstore.Receipt) error {
			return s.recordDriftResultWithin(ctx, tx, tenant, r.RequestID)
		}
	}
	_, err = s.Store.MutateChange(ctx, mutation, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		var commandRaw []byte
		if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, tenant, r.CommandID).Scan(&commandRaw); err != nil {
			return nil, err
		}
		var command PreparedCommand
		if err := json.Unmarshal(commandRaw, &command); err != nil {
			return nil, err
		}
		if c.State != domain.Executing || c.ExecutionID != r.CommandID || r.RequestID != command.RequestID || r.CorrelationID != command.CorrelationID || r.EnvelopeDigest != command.EnvelopeDigest {
			if command.Purpose == "EXPIRE_GRANT" && c.State == domain.Executed && c.ExpiryStatus == "REVOKING" && c.ExpiryExecutionID == r.CommandID && r.RequestID == command.RequestID && r.CorrelationID == command.CorrelationID && r.EnvelopeDigest == command.EnvelopeDigest {
				return s.expiryResult(ctx, tx, now, c, command, r)
			}
			return nil, ErrPermission
		}
		// Uncertain application stays EXECUTING for reconciliation. It is never
		// converted into a grant, blind redispatch or an invented failed write.
		if command.Kubernetes != nil {
			return s.nativeExecutionResult(ctx, tx, now, c, command, r, digest)
		}
		if r.Kubernetes != nil {
			return nil, ErrPermission
		}
		if !r.ReadBackVerified {
			events, err := domain.Decide(c, domain.Command{Kind: "RECONCILE", At: now, ExecutionID: c.ExecutionID})
			if err != nil {
				return nil, err
			}
			if err := s.enqueue(ctx, tx, JobArgs{tenant, c.ID, c.Revision + 1, "reconcile"}); err != nil {
				return nil, err
			}
			facts, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			events[0].Change.Facts = facts
			return events, nil
		}
		roles := slices.Clone(r.ObservedRoles)
		slices.Sort(roles)
		observedDigest, err := canon.New().Digest(struct {
			Tenant, Target string
			Roles          []string
			Revision       int64
			At             time.Time
		}{r.ObservedTenant, r.ObservedTarget, roles, r.ObservedRevision, r.ObservedAt})
		if err != nil {
			return nil, err
		}
		if r.ObservedTenant != tenant || r.ObservedTarget != c.Intent.Target || r.ObservedAt.Before(command.DispatchedAt) || r.ObservedAt.After(now.Add(time.Minute)) || observedDigest != r.ObservationDigest {
			return nil, ErrPermission
		}
		isRoleOp := command.Envelope.Intent.Kind == "ROLE_ASSIGN" || command.Envelope.Intent.Kind == "ROLE_REVOKE"
		if !r.Success {
			if !r.AppliedAt.IsZero() || r.ObservedRevision != command.ExpectedRevision || (isRoleOp && !slices.Equal(roles, command.BeforeRoles)) {
				return nil, ErrPermission
			}
			events, err := domain.Decide(c, domain.Command{Kind: "EXECUTION_FAILED", At: now, ExecutionID: r.CommandID, Reason: "connector refused change; unchanged state independently observed"})
			if err != nil {
				return nil, err
			}
			facts, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			events[0].Change.Facts = facts
			return events, nil
		}
		if !applicationTimeValid(command, r) || r.ObservedRevision != command.ExpectedRevision+1 || (isRoleOp && !slices.Equal(roles, command.ExpectedRoles)) {
			return nil, ErrPermission
		}
		events, err := domain.Decide(c, domain.Command{Kind: "VERIFIED", At: now, ExecutionID: r.CommandID, Verified: true})
		if err != nil {
			return nil, err
		}
		facts, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		events[0].Change.Facts = facts
		return events, nil
	})
	if errors.Is(err, eventstore.ErrVersionConflict) {
		return ErrDependency
	}
	return err
}

func applicationTimeValid(command PreparedCommand, result ExecutionResult) bool {
	return !result.AppliedAt.IsZero() && !result.AppliedAt.Before(command.DispatchedAt) && !result.AppliedAt.After(command.Deadline) && !result.AppliedAt.After(result.ObservedAt)
}

func (s *Service) Reconcile(ctx context.Context, args JobArgs) error {
	current, err := s.Store.ReadChange(ctx, args.Tenant, args.Request)
	if err != nil {
		return err
	}
	if current.State != domain.Executing {
		return nil
	}
	digest, err := canon.New().Digest(args)
	if err != nil {
		return err
	}
	execution := s.executions[args.Tenant]
	if execution == nil {
		return ErrDependency
	}
	var query PreparedCommand
	var stamp time.Time
	m := eventstore.ChangeMutation{TenantID: args.Tenant, ActorID: "core-reconciler", RequestID: args.Request, ID: jobID(args), ExpectedRevision: args.Revision, InputDigest: digest}
	m.Additional = func(tx pgx.Tx, r eventstore.Receipt) error {
		raw, err := json.Marshal(query)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.outbox(tenant_id,event_id,sequence,subject,payload,created_at) VALUES($1,$2,$3,$4,$5,$6)`, args.Tenant, query.MessageID, r.LastSequence, "ratchet."+args.Tenant+".exec."+execution.Connector, raw, stamp)
		return err
	}
	_, err = s.Store.MutateChange(ctx, m, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, args.Tenant, c.ExecutionID).Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &query); err != nil {
			return nil, err
		}
		query.MessageID = uuid.NewSHA1(jobID(args), []byte("verify-only")).String()
		query.VerifyOnly = true
		query.Signature = nil
		hash, err := signingDigest("RATCHET_EXEC_COMMAND_V1", query)
		if err != nil {
			return nil, err
		}
		query.Signature = ed25519.Sign(execution.private, hash[:])
		stamp = now
		// A lost read-back reply must not end recovery. Persist the next probe in
		// this transaction; every probe is read-only and terminal states stop it.
		if err := s.scheduleReconciliation(ctx, tx, c, now); err != nil {
			return nil, err
		}
		return domain.Decide(c, domain.Command{Kind: "RECONCILE", At: now, ExecutionID: c.ExecutionID})
	})
	if errors.Is(err, eventstore.ErrVersionConflict) {
		return nil
	}
	return err
}

func (s *Service) recordContainmentResult(ctx context.Context, tenant string, r ExecutionResult, command PreparedCommand) error {
	if r.SchemaVersion != 1 || r.Tenant != tenant || r.Connector != command.Connector {
		return ErrPermission
	}
	if r.CommandID != command.CommandID || r.RequestID != command.RequestID || r.CorrelationID != command.CorrelationID || r.EnvelopeDigest != command.EnvelopeDigest {
		return ErrPermission
	}
	if r.ObservedTenant != tenant || r.ObservedTarget != command.Envelope.Intent.Target {
		return ErrPermission
	}
	roles := slices.Clone(r.ObservedRoles)
	slices.Sort(roles)
	observedDigest, err := canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{r.ObservedTenant, r.ObservedTarget, roles, r.ObservedRevision, r.ObservedAt})
	if err != nil || observedDigest != r.ObservationDigest {
		return ErrPermission
	}
	if !r.ReadBackVerified || !r.Success {
		return s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
			incident, err := s.incidentWithin(ctx, tx, tenant, command.IncidentReference, 0)
			if err != nil {
				return err
			}
			reviewIncident := Incident{
				ID:              incident.ID,
				Tenant:          tenant,
				CorrelationID:   incident.CorrelationID,
				Identity:        incident.Identity,
				PlanID:          incident.PlanID,
				PlanDigest:      incident.PlanDigest,
				Status:          "REVIEW",
				OpenedAt:        incident.OpenedAt,
				Revision:        incident.Revision + 1,
				OpenFingerprint: incident.OpenFingerprint,
			}
			raw, err := json.Marshal(reviewIncident)
			if err != nil {
				return err
			}
			msgID, err := uuid.Parse(r.MessageID)
			if err != nil {
				msgID = uuid.New()
			}
			_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{
				TenantID:        tenant,
				ID:              uuid.NewSHA1(msgID, []byte("residual-review")),
				StreamID:        "incident:" + incident.ID,
				ExpectedVersion: incident.Revision,
				ActorReference:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":connector:"+command.Connector)),
				Events:          []eventstore.Event{{Type: "IncidentResidualReviewRequired", Facts: raw}},
			})
			return err
		})
	}
	return s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		incident, err := s.incidentWithin(ctx, tx, tenant, command.IncidentReference, 0)
		if err != nil {
			return err
		}
		proposal, err := s.containmentProposal(ctx, tx, tenant, incident.PlanID)
		if err != nil {
			return err
		}
		rBytes, err := json.Marshal(r)
		if err != nil {
			return err
		}
		msgID, err := uuid.Parse(r.MessageID)
		if err != nil {
			msgID = uuid.New()
		}
		if _, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{
			TenantID:       tenant,
			ID:             uuid.NewSHA1(msgID, []byte("action-verified")),
			StreamID:       "containment:" + proposal.Body.ID,
			ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":connector:"+command.Connector)),
			Events:         []eventstore.Event{{Type: "ContainmentActionVerified", Facts: rBytes}},
		}); err != nil {
			return err
		}
		events, err := s.Store.StreamWithin(ctx, tx, tenant, "containment:"+proposal.Body.ID)
		if err != nil {
			return err
		}
		verifiedReqIDs := make(map[string]bool)
		for _, ev := range events {
			if ev.Type == "ContainmentActionVerified" {
				var content struct {
					Payload json.RawMessage `json:"payload"`
				}
				var payload struct {
					Facts json.RawMessage `json:"facts"`
				}
				if json.Unmarshal(ev.Entry.Canonical, &content) == nil && json.Unmarshal(content.Payload, &payload) == nil {
					var result ExecutionResult
					if json.Unmarshal(payload.Facts, &result) == nil && result.Success && result.ReadBackVerified {
						verifiedReqIDs[result.RequestID] = true
					}
				}
			}
		}

		allActionsVerified := len(proposal.Body.Plan.Actions) > 0
		for i := range proposal.Body.Plan.Actions {
			actionReqID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(proposal.Body.ID+fmt.Sprintf(":%d", i))).String()
			if !verifiedReqIDs[actionReqID] {
				allActionsVerified = false
				break
			}
		}

		if allActionsVerified {
			// Check connector source is not in resync quarantine
			var sourceQuarantine bool
			_ = tx.QueryRow(ctx, `SELECT needs_resync FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id=$2`, tenant, command.Connector).Scan(&sourceQuarantine)
			if sourceQuarantine {
				return nil
			}

			// Verify current residual reach is zero before transitioning incident to CONTAINED
			currentSnapshot, _, err := s.context(ctx, tx, Actor{TenantID: tenant, ID: "containment-verifier"}, "containment_verify", nil)
			if err == nil && currentSnapshot != nil {
				paths, err := currentSnapshot.PathsTo(incident.Identity, 1000, 1_000_000)
				if err == nil && len(paths.Routes) > 0 {
					return nil // Residual reach remains on current graph
				}
			}

			containedIncident := Incident{
				ID:              incident.ID,
				Tenant:          tenant,
				CorrelationID:   incident.CorrelationID,
				Identity:        incident.Identity,
				PlanID:          proposal.Body.ID,
				PlanDigest:      proposal.Digest,
				Status:          "CONTAINED",
				OpenedAt:        incident.OpenedAt,
				Revision:        incident.Revision + 1,
				OpenFingerprint: incident.OpenFingerprint,
				ContainedAt:     now,
			}
			containedRaw, err := json.Marshal(containedIncident)
			if err != nil {
				return err
			}
			_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{
				TenantID:        tenant,
				ID:              uuid.NewSHA1(msgID, []byte("incident-contained")),
				StreamID:        "incident:" + incident.ID,
				ExpectedVersion: incident.Revision,
				ActorReference:  uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":connector:"+command.Connector)),
				Events:          []eventstore.Event{{Type: "IncidentContained", Facts: containedRaw}},
			})
			return err
		}
		return nil
	})
}
