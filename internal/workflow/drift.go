package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type DriftObservation struct {
	DriftID     string    `json:"drift_id"`
	OperationID string    `json:"operation_id"`
	Tenant      string    `json:"tenant_id"`
	Connector   string    `json:"connector_id"`
	Correlation string    `json:"correlation_id"`
	CommandID   string    `json:"command_id"`
	Action      string    `json:"action"`
	Target      string    `json:"target"`
	Access      string    `json:"access"`
	Revision    int64     `json:"observed_revision"`
	ObservedAt  time.Time `json:"observed_at"`
}
type DriftReceipt struct {
	Observation     DriftObservation `json:"observation"`
	Outcome         string           `json:"outcome"`
	IncidentID      string           `json:"incident_id"`
	RequestID       string           `json:"corrective_request_id"`
	ReportDigest    ports.Digest     `json:"report_digest"`
	ReductionDigest ports.Digest     `json:"reduction_digest"`
	At              time.Time        `json:"at"`
}

func DriftSigningDigest(message *v1.SignedDriftReport) (ports.Digest, error) {
	if message == nil {
		return ports.Digest{}, domain.ErrInvalid
	}
	copyMessage := proto.Clone(message).(*v1.SignedDriftReport)
	copyMessage.Signature = nil
	raw, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(copyMessage)
	if err != nil {
		return ports.Digest{}, err
	}
	canonical, err := canon.New().Canonicalize(raw)
	if err != nil {
		return ports.Digest{}, err
	}
	return canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   []byte `json:"canonical_proto_json"`
	}{"RATCHET_DRIFT_REPORT_V1", canonical})
}

func (s *Service) RecordDrift(ctx context.Context, tenant string, raw []byte) (receipt DriftReceipt, err error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return receipt, domain.ErrInvalid
	}
	nativeEnvelope := new(v1.SignedKubernetesDriftReport)
	if protojson.Unmarshal(raw, nativeEnvelope) == nil && len(nativeEnvelope.SignedKubernetesDriftJson) > 0 {
		native, err := s.RecordKubernetesDrift(ctx, tenant, nativeEnvelope.SignedKubernetesDriftJson)
		if err != nil {
			return receipt, err
		}
		return DriftReceipt{Observation: DriftObservation{DriftID: native.DriftID, OperationID: native.OperationID, Tenant: native.Tenant, Connector: native.Connector, Correlation: native.CorrelationID, Target: native.ObjectKey, Revision: native.SourceRevision}, Outcome: native.Outcome, IncidentID: native.IncidentID, ReportDigest: native.InputDigest, At: native.At}, nil
	}
	message := new(v1.SignedDriftReport)
	if protojson.Unmarshal(raw, message) != nil {
		return receipt, domain.ErrInvalid
	}
	report := message.GetReport()
	e := report.GetEnvelope()
	op := report.GetUnapprovedOperation()
	if e == nil || op == nil || e.SchemaVersion != 1 || e.TenantId != tenant || report.TenantId != tenant || op.TenantId != tenant || report.ConnectorId != e.ConnectorId || report.ObservedRevision < 1 || report.ObservedRevision > 1<<53-1 || e.SourceRevision != report.ObservedRevision {
		return receipt, ErrPermission
	}
	execution := s.executions[tenant]
	if execution == nil || execution.Connector != e.ConnectorId {
		return receipt, ErrDependency
	}
	digest, err := DriftSigningDigest(message)
	if err != nil || !ed25519.Verify(execution.public, digest[:], message.Signature) {
		return receipt, ErrPermission
	}
	for _, id := range []string{e.MessageId, e.CorrelationId, report.DriftId, op.EventId} {
		if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil || parsed.String() != id {
			return receipt, domain.ErrInvalid
		}
	}
	if op.CorrelationId != e.CorrelationId {
		return receipt, ErrPermission
	}
	if len(op.Action) > 64 || len(op.Target) > 256 || len(op.Details["resource_or_role"]) > 256 {
		return receipt, domain.ErrInvalid
	}
	if inner := op.Envelope; inner != nil && (inner.SchemaVersion != 1 || inner.TenantId != tenant || inner.ConnectorId != e.ConnectorId || inner.CorrelationId != e.CorrelationId || inner.CommandId != e.CommandId || inner.SourceRevision != e.SourceRevision) {
		return receipt, ErrPermission
	}
	if e.CommandId != "" {
		if id, err := uuid.Parse(e.CommandId); err != nil || id == uuid.Nil || id.String() != e.CommandId {
			return receipt, domain.ErrInvalid
		}
	}
	at, err := time.Parse(time.RFC3339Nano, op.Timestamp)
	if err != nil {
		return receipt, domain.ErrInvalid
	}
	detected, err := time.Parse(time.RFC3339Nano, report.DetectedAt)
	if err != nil || detected.Before(at) {
		return receipt, domain.ErrInvalid
	}
	observation := DriftObservation{DriftID: report.DriftId, OperationID: op.EventId, Tenant: tenant, Connector: e.ConnectorId, Correlation: e.CorrelationId, CommandID: e.CommandId, Action: op.Action, Target: op.Target, Access: op.Details["resource_or_role"], Revision: report.ObservedRevision, ObservedAt: at.UTC()}
	// Transport IDs and the new drift ID do not define the semantic observation.
	identity := observation
	identity.DriftID = ""
	inputDigest, err := canon.New().Digest(identity)
	if err != nil {
		return receipt, err
	}
	ctx, span := s.observer.Start(ctx, "drift_observation", tenant, e.CorrelationId)
	defer func() { span.End(err) }()
	err = s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		if at.After(now.Add(time.Minute)) || detected.After(now.Add(time.Minute)) {
			return domain.ErrInvalid
		}
		var prior, document []byte
		err := tx.QueryRow(ctx, `SELECT input_digest,document FROM ratchet.drift_receipts WHERE tenant_id=$1 AND connector_id=$2 AND (operation_id=$3::uuid OR drift_id=$4::uuid) ORDER BY CASE WHEN drift_id=$4::uuid THEN 0 ELSE 1 END`, tenant, e.ConnectorId, op.EventId, report.DriftId).Scan(&prior, &document)
		if err == nil {
			if string(prior) != string(inputDigest[:]) {
				return eventstore.ErrIdempotencyConflict
			}
			return json.Unmarshal(document, &receipt)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		responder := s.config.DriftResponders[tenant]
		if responder == "" {
			return ErrDependency
		}
		snapshot, active, err := s.context(ctx, tx, Actor{TenantID: tenant, ID: responder}, "drift_manage", nil)
		if err != nil {
			return err
		}
		var revision int64
		var source []byte
		var quarantine bool
		if err := tx.QueryRow(ctx, `SELECT source_revision,public_graph,needs_resync FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id=$2`, tenant, e.ConnectorId).Scan(&revision, &source, &quarantine); err != nil {
			return err
		}
		if quarantine || revision < observation.Revision {
			return ErrDependency
		}
		receipt = DriftReceipt{Observation: observation, ReportDigest: digest, At: now, Outcome: "HELD_FOR_REVIEW"}
		if revision > observation.Revision {
			receipt.Outcome = "STALE_OBSERVATION"
		} else {
			matched, err := s.correlateDrift(ctx, tx, observation, source)
			if err != nil {
				return err
			}
			if matched {
				receipt.Outcome = "CORRELATED_APPROVED_COMMAND"
			} else {
				if _, err := snapshot.Node(observation.Target); err != nil {
					return domain.ErrInvalid
				}
				receipt.IncidentID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+e.ConnectorId+":drift-incident:"+op.EventId)).String()
				incident := Incident{ID: receipt.IncidentID, Tenant: tenant, Identity: observation.Target, CorrelationID: observation.Correlation, Status: "OPEN", OpenedAt: now, Revision: 1, OpenFingerprint: inputDigest, Origin: "DRIFT", SourceDrift: report.DriftId}
				if observation.Action == "ASSIGN_ROLE" {
					action := graph.Revocation{Kind: "ROLE_REVOKE", Target: observation.Target, Access: observation.Access}
					delta, proofErr := s.driftRevocationDelta(ctx, tx, snapshot, observation, action)
					if proofErr == nil {
						impact, proofErr := snapshot.ImpactDiff(delta)
						if proofErr == nil && impact.MonotonicReduction {
							receipt.ReductionDigest, err = canon.New().Digest(impact)
							if err != nil {
								return err
							}
							intent := domain.Intent{Kind: "ROLE_REVOKE", Target: observation.Target, Access: observation.Access}
							decision, err := s.decidePolicy(ctx, tenant, observation.Correlation, active, factsFor(ctx, snapshot, active, domain.Change{Requester: responder, Intent: intent}, impact))
							if err != nil {
								return err
							}
							if decision.Outcome == "ALLOW" && execution.capability.ProvenReductions {
								receipt.RequestID, err = s.stageDriftReduction(ctx, tx, now, Actor{TenantID: tenant, ID: responder}, snapshot, active, receipt, intent, decision, impact)
								if err != nil {
									return err
								}
								receipt.Outcome = "CORRECTIVE_COMMAND_STAGED"
								incident.CorrectiveRequest = receipt.RequestID
								incident.Status = "CONTAINING"
							}
						}
					}
				}
				facts, err := json.Marshal(incident)
				if err != nil {
					return err
				}
				if _, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.MustParse(incident.ID), []byte("open")), StreamID: "incident:" + incident.ID, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+responder)), Events: []eventstore.Event{{Type: "IncidentDriftOpened", Facts: facts}}}); err != nil {
					return err
				}
			}
		}
		private, err := eventstore.SealPrivate(s.key, tenant, uuid.NewSHA1(uuid.MustParse(op.EventId), []byte("drift-private")), "workflow-v1", raw)
		if err != nil {
			return err
		}
		document, err = json.Marshal(receipt)
		if err != nil {
			return err
		}
		record, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.MustParse(op.EventId), []byte(tenant+":"+e.ConnectorId+":observed")), StreamID: "drift:" + op.EventId, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":connector:"+e.ConnectorId)), Events: []eventstore.Event{{Type: "DriftObserved", Facts: document, Private: &private}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.drift_receipts(tenant_id,connector_id,drift_id,operation_id,input_digest,document,event_position) VALUES($1,$2,$3::uuid,$4::uuid,$5,$6,$7)`, tenant, e.ConnectorId, report.DriftId, op.EventId, inputDigest.Bytes(), document, record.LastSequence)
		return err
	})
	return receipt, err
}

func (s *Service) correlateDrift(ctx context.Context, tx pgx.Tx, o DriftObservation, source []byte) (bool, error) {
	if o.CommandID == "" {
		return false, nil
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, o.Tenant, o.CommandID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var cmd PreparedCommand
	if json.Unmarshal(raw, &cmd) != nil {
		return false, eventstore.ErrIntegrity
	}
	if cmd.Tenant != o.Tenant || cmd.Connector != o.Connector || cmd.CorrelationID != o.Correlation || cmd.Envelope == nil || cmd.Envelope.Intent.Target != o.Target || o.Revision != cmd.ExpectedRevision+1 || o.ObservedAt.Before(cmd.DispatchedAt) || o.ObservedAt.After(cmd.Deadline) {
		return false, nil
	}
	c, err := s.Store.ChangeWithin(ctx, tx, o.Tenant, cmd.RequestID)
	if err != nil {
		return false, err
	}
	if cmd.Purpose == "EXPIRE_GRANT" {
		if c.ExpiryExecutionID != cmd.CommandID || c.ExpiryStatus == "FAILED" {
			return false, nil
		}
	} else if c.ExecutionID != cmd.CommandID || (c.State != domain.Executing && c.State != domain.Executed) {
		return false, nil
	}
	roles := []string{}
	var data graph.Data
	if json.Unmarshal(source, &data) != nil {
		return false, eventstore.ErrIntegrity
	}
	for _, edge := range data.Edges {
		if edge.Source == o.Target && edge.Kind == "ASSIGNED" {
			roles = append(roles, edge.Target)
		}
	}
	slices.Sort(roles)
	roles = slices.Compact(roles)
	if !slices.Equal(roles, cmd.ExpectedRoles) {
		return false, nil
	}
	if o.Action == "ASSIGN_ROLE" {
		if cmd.Envelope.Intent.Kind == "ROLE_ASSIGN" && cmd.Envelope.Intent.Access == o.Access && slices.Contains(cmd.ExpectedRoles, o.Access) {
			return true, nil
		}
		return !slices.Contains(cmd.BeforeRoles, o.Access) && slices.Contains(cmd.ExpectedRoles, o.Access), nil
	}
	if o.Action == "REVOKE_ROLE" {
		return slices.Contains(cmd.BeforeRoles, o.Access) && !slices.Contains(cmd.ExpectedRoles, o.Access), nil
	}
	return false, nil
}

// Protected/removability metadata is checked against the authenticated retained
// source, not a privacy-stripped projection. Without that evidence automation
// holds. The reduction includes only assignment IDs owned by this connector.
func (s *Service) driftRevocationDelta(ctx context.Context, tx pgx.Tx, snapshot *graph.Snapshot, o DriftObservation, action graph.Revocation) (graph.Delta, error) {
	var record eventstore.PrivateRecord
	if err := tx.QueryRow(ctx, `SELECT p.record_id,p.key_reference,p.ciphertext FROM ratchet.graph_sources s JOIN ratchet.private_records p ON p.tenant_id=s.tenant_id AND p.record_id=s.private_record_id WHERE s.tenant_id=$1 AND s.connector_id=$2 AND s.source_revision=$3`, o.Tenant, o.Connector, o.Revision).Scan(&record.ID, &record.KeyReference, &record.Ciphertext); err != nil {
		return graph.Delta{}, err
	}
	raw, err := eventstore.OpenPrivate(s.key, o.Tenant, record)
	if err != nil {
		return graph.Delta{}, err
	}
	var source graph.Data
	if json.Unmarshal(raw, &source) != nil {
		return graph.Delta{}, eventstore.ErrIntegrity
	}
	protected := func(props map[string]string) bool {
		return (props["protected"] != "" && props["protected"] != "false") || (props["removable"] != "" && props["removable"] != "true")
	}
	for _, n := range source.Nodes {
		if n.ID == o.Target && protected(n.Properties) {
			return graph.Delta{}, ErrPermission
		}
	}
	ids := map[string]bool{}
	for _, edge := range source.Edges {
		if edge.Source == o.Target && edge.Target == o.Access && edge.Kind == "ASSIGNED" {
			if protected(edge.Properties) {
				return graph.Delta{}, ErrPermission
			}
			ids[graph.EdgeID(edge)] = true
		}
	}
	if len(ids) == 0 {
		return graph.Delta{}, ErrPermission
	}
	delta, err := snapshot.RevocationDelta(action)
	if err != nil {
		return delta, err
	}
	delta.EdgesRemoved = slices.DeleteFunc(delta.EdgesRemoved, func(id string) bool { return !ids[id] })
	if len(delta.EdgesRemoved) != len(ids) {
		return graph.Delta{}, eventstore.ErrIntegrity
	}
	return delta, nil
}
