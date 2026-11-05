package workflow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// SignedKubernetesDrift is connector watch evidence. Before must match a
// previously committed native source digest; it cannot invent a trusted baseline.
type SignedKubernetesDrift struct {
	SchemaVersion        int               `json:"schema_version"`
	Tenant               string            `json:"tenant_id"`
	Connector            string            `json:"connector_id"`
	Cluster              string            `json:"cluster_id"`
	DriftID              string            `json:"drift_id"`
	OperationID          string            `json:"operation_id"`
	CorrelationID        string            `json:"correlation_id"`
	BaselineGraphVersion int64             `json:"baseline_graph_version"`
	SourceRevision       int64             `json:"source_revision"`
	Before               kube.State        `json:"before"`
	Mutation             kube.Mutation     `json:"mutation"`
	Observation          NativeObservation `json:"observation"`
	CommandID            string            `json:"command_id"`
	AppliedAt            time.Time         `json:"applied_at"`
	ObservedAt           time.Time         `json:"observed_at"`
	Signature            []byte            `json:"signature"`
}

type KubernetesDriftReceipt struct {
	DriftID              string          `json:"drift_id"`
	OperationID          string          `json:"operation_id"`
	Tenant               string          `json:"tenant_id"`
	Connector            string          `json:"connector_id"`
	CorrelationID        string          `json:"correlation_id"`
	ObjectKey            string          `json:"object_key"`
	SourceKey            string          `json:"source_key"`
	SourceRevision       int64           `json:"source_revision"`
	BaselineGraphVersion int64           `json:"baseline_graph_version"`
	GraphVersion         int64           `json:"graph_version"`
	BeforeDigest         string          `json:"before_digest"`
	AfterDigest          string          `json:"after_digest"`
	InputDigest          ports.Digest    `json:"input_digest"`
	MutationDigest       ports.Digest    `json:"mutation_digest"`
	Outcome              string          `json:"outcome"`
	IncidentID           string          `json:"incident_id"`
	Decision             domain.Decision `json:"decision"`
	PolicyDigest         ports.Digest    `json:"policy_digest"`
	RegistryDigest       ports.Digest    `json:"registry_digest"`
	RegistryEpoch        int64           `json:"registry_epoch"`
	Impact               *graph.Impact   `json:"impact,omitempty"`
	Replay               *KubernetesPlan `json:"replay,omitempty"`
	Facts                *recordedFacts  `json:"policy_facts,omitempty"`
	At                   time.Time       `json:"at"`
}

func KubernetesDriftSigningDigest(message SignedKubernetesDrift) (ports.Digest, error) {
	message.Signature = nil
	return signingDigest("RATCHET_KUBERNETES_DRIFT_V1", message)
}

func (s *Service) RecordKubernetesDrift(ctx context.Context, tenant string, raw []byte) (receipt KubernetesDriftReceipt, err error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return receipt, domain.ErrInvalid
	}
	var message SignedKubernetesDrift
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&message) != nil || decoder.Decode(new(any)) != io.EOF {
		return receipt, domain.ErrInvalid
	}
	if message.SchemaVersion != 1 || message.Tenant != tenant || message.Mutation.Connector != message.Connector || message.Mutation.Cluster != message.Cluster || message.Before.Cluster != message.Cluster || message.Before.ValidateObserved() != nil || message.Mutation.Validate() != nil || message.BaselineGraphVersion < 1 || message.BaselineGraphVersion > 1<<53-1 || message.SourceRevision < 1 || message.SourceRevision > 1<<53-1 || message.ObservedAt.IsZero() || message.AppliedAt.IsZero() || message.ObservedAt.Before(message.AppliedAt) {
		return receipt, domain.ErrInvalid
	}
	for _, id := range []string{message.DriftID, message.OperationID, message.CorrelationID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return receipt, domain.ErrInvalid
		}
	}
	if message.CommandID != "" {
		id, err := uuid.Parse(message.CommandID)
		if err != nil || id == uuid.Nil || id.String() != message.CommandID {
			return receipt, domain.ErrInvalid
		}
	}
	pin, err := s.kubernetesPin(kube.Admission{Tenant: tenant, Mutation: message.Mutation})
	if err != nil {
		return receipt, err
	}
	digest, err := KubernetesDriftSigningDigest(message)
	if err != nil || !ed25519.Verify(pin.PublicKey, digest[:], message.Signature) {
		return receipt, ErrPermission
	}
	// Transport drift IDs do not defeat semantic observation deduplication.
	semantic := message
	semantic.DriftID, semantic.Signature = "", nil
	inputDigest, err := canon.New().Digest(semantic)
	if err != nil {
		return receipt, err
	}
	ctx, span := s.observer.Start(ctx, "drift_observation", tenant, message.CorrelationID)
	defer func() { span.End(err) }()
	err = s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		if message.ObservedAt.After(now.Add(time.Minute)) {
			return domain.ErrInvalid
		}
		var prior, document []byte
		err := tx.QueryRow(ctx, `SELECT input_digest,document FROM ratchet.native_drift_receipts WHERE tenant_id=$1 AND connector_id=$2 AND (operation_id=$3::uuid OR drift_id=$4::uuid) ORDER BY CASE WHEN drift_id=$4::uuid THEN 0 ELSE 1 END`, tenant, pin.Connector, message.OperationID, message.DriftID).Scan(&prior, &document)
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
		key := graph.KubernetesSourceKey(message.Cluster)
		current, revision, err := s.Store.KubernetesSourceWithin(ctx, tx, tenant, pin.Connector, key, s.key)
		if err != nil || revision < message.SourceRevision {
			return ErrDependency
		}
		baseline, err := s.Store.GraphAtWithin(ctx, tx, tenant, message.BaselineGraphVersion)
		if err != nil {
			return err
		}
		beforeDigest, err := graph.KubernetesStateDigest(message.Before)
		if err != nil || baseline.Data().KubernetesDigests[key] != beforeDigest {
			return ErrPermission
		}
		mutationDigest, err := canon.New().Digest(message.Mutation)
		if err != nil {
			return err
		}
		afterDigest, err := graph.KubernetesStateDigest(current)
		if err != nil {
			return err
		}
		receipt = KubernetesDriftReceipt{DriftID: message.DriftID, OperationID: message.OperationID, Tenant: tenant, Connector: pin.Connector, CorrelationID: message.CorrelationID, ObjectKey: NativeObjectKey(message.Mutation), SourceKey: key, SourceRevision: message.SourceRevision, BaselineGraphVersion: message.BaselineGraphVersion, GraphVersion: snapshot.Version(), BeforeDigest: beforeDigest, AfterDigest: afterDigest, InputDigest: inputDigest, MutationDigest: mutationDigest, Outcome: "HELD_FOR_REVIEW", Decision: domain.Decision{Outcome: "HOLD", Reasons: []string{"complete exact drift context required"}}, PolicyDigest: active.Hash, RegistryDigest: active.RegistryDigest, RegistryEpoch: active.RegistryEpoch, At: now}
		if revision > message.SourceRevision {
			receipt.Outcome = "STALE_OBSERVATION"
		} else {
			proved := observedNativeTransition(message, current)
			if proved {
				plan, err := ephemeralKubernetesPlan(message.Before, message.Mutation)
				if err != nil {
					return err
				}
				actual, err := graph.CompileKubernetes(snapshot.Version(), current)
				if err != nil {
					return err
				}
				plan.Current = actual.Data()
				plan.SourceDigest, err = ports.DigestFromHex(afterDigest)
				if err != nil {
					return err
				}
				plan.SourceRevision, plan.Version, plan.Tenant, plan.Connector, plan.MutationDigest, plan.ObjectKey, plan.Operation = revision, 1, tenant, pin.Connector, mutationDigest, receipt.ObjectKey, message.Mutation.Operation
				view, err := nativeAssociations(snapshot, active, actual.Data())
				if err != nil {
					return err
				}
				before, _, impact, _, err := view.KubernetesProjection(actual.Data(), plan.Before, plan.After)
				if err != nil {
					return err
				}
				facts := factsFor(ctx, before, active, domain.Change{TenantID: tenant, Requester: responder, Intent: domain.Intent{Kind: "K8S_RBAC_CHANGE", Target: receipt.ObjectKey, Access: message.Mutation.Operation}}, impact)
				receipt.Decision, err = s.decidePolicy(ctx, tenant, message.CorrelationID, active, facts)
				if err != nil {
					return err
				}
				graphDigest, err := canon.New().Digest(before.Data())
				if err != nil {
					return err
				}
				receipt.Impact, receipt.Replay, receipt.Facts = &impact, &plan, &recordedFacts{Evaluator: evaluatorVersion, Input: facts, GraphDigest: graphDigest}
				matched, err := s.correlateNativeDrift(ctx, tx, message, receipt)
				if err != nil {
					return err
				}
				if matched {
					receipt.Outcome = "CORRELATED_APPROVED_COMMAND"
				}
			}
			if receipt.Outcome != "CORRELATED_APPROVED_COMMAND" {
				receipt.IncidentID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+pin.Connector+":native-drift:"+message.OperationID)).String()
				identity := receipt.ObjectKey
				if receipt.Impact != nil {
					for _, impact := range receipt.Impact.Affected {
						if _, err := snapshot.Node(impact.IdentityID); err == nil {
							identity = impact.IdentityID
							break
						}
					}
				}
				incident := Incident{ID: receipt.IncidentID, Tenant: tenant, Identity: identity, CorrelationID: message.CorrelationID, Status: "OPEN", OpenedAt: now, Revision: 1, OpenFingerprint: inputDigest, Origin: "DRIFT", SourceDrift: message.DriftID, Kubernetes: &receipt}
				facts, err := json.Marshal(incident)
				if err != nil {
					return err
				}
				if _, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.MustParse(incident.ID), []byte("open")), StreamID: "incident:" + incident.ID, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":"+responder)), Events: []eventstore.Event{{Type: "IncidentDriftOpened", Facts: facts}}}); err != nil {
					return err
				}
			}
		}
		private, err := eventstore.SealPrivate(s.key, tenant, uuid.NewSHA1(uuid.MustParse(message.OperationID), []byte(tenant+":"+pin.Connector+":native-drift")), "native-drift-v1", raw)
		if err != nil {
			return err
		}
		document, err = json.Marshal(receipt)
		if err != nil {
			return err
		}
		record, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: tenant, ID: uuid.NewSHA1(uuid.MustParse(message.OperationID), []byte(tenant+":"+pin.Connector+":native-observed")), StreamID: "native-drift:" + message.OperationID, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(tenant+":connector:"+pin.Connector)), Events: []eventstore.Event{{Type: "KubernetesDriftObserved", Facts: document, Private: &private}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.native_drift_receipts(tenant_id,connector_id,drift_id,operation_id,input_digest,document,event_position) VALUES($1,$2,$3::uuid,$4::uuid,$5,$6,$7)`, tenant, pin.Connector, message.DriftID, message.OperationID, inputDigest.Bytes(), document, record.LastSequence)
		return err
	})
	return receipt, err
}

func observedNativeTransition(message SignedKubernetesDrift, current kube.State) bool {
	if message.BaselineGraphVersion < 1 || message.Before.ResourceVersion == current.ResourceVersion {
		return false
	}
	if _, err := message.Before.After(message.Mutation); err != nil {
		return false
	}
	observation := message.Observation
	if message.Mutation.Operation == "DELETE" {
		if observation.Object != nil || observation.DeletedUID != message.Mutation.Before.UID {
			return false
		}
	} else {
		if observation.Object == nil || observation.Object.Validate() != nil || observation.Object.UID == "" || observation.Object.ResourceVersion == "" || observation.DeletedUID != "" {
			return false
		}
		want, got := *message.Mutation.After, *observation.Object
		if message.Mutation.Before != nil && (got.UID != message.Mutation.Before.UID || got.ResourceVersion == message.Mutation.Before.ResourceVersion) {
			return false
		}
		want.UID, want.ResourceVersion, got.UID, got.ResourceVersion = "", "", "", ""
		if !sameNativeObject(&want, &got) {
			return false
		}
	}
	// Other simultaneous source changes require a separate observation/proof.
	expected, err := message.Before.Clone()
	if err != nil {
		return false
	}
	expected.ResourceVersion = current.ResourceVersion
	target := message.Mutation.After
	if target == nil {
		target = message.Mutation.Before
	}
	expected.Objects = slices.DeleteFunc(expected.Objects, func(o kube.Object) bool { return kube.ObjectKey(o) == kube.ObjectKey(*target) })
	if observation.Object != nil {
		expected.Objects = append(expected.Objects, *observation.Object)
	}
	a, err := graph.KubernetesStateDigest(expected)
	if err != nil {
		return false
	}
	b, err := graph.KubernetesStateDigest(current)
	return err == nil && a == b
}

func (s *Service) correlateNativeDrift(ctx context.Context, tx pgx.Tx, message SignedKubernetesDrift, receipt KubernetesDriftReceipt) (bool, error) {
	if message.CommandID == "" {
		return false, nil
	}
	var request, admission string
	var contextDigest, mutationDigest []byte
	var authorized, expires time.Time
	err := tx.QueryRow(ctx, `SELECT request_id::text,admission_uid,context_digest,mutation_digest,authorized_at,expires_at FROM ratchet.native_admissions WHERE tenant_id=$1 AND connector_id=$2 AND command_id=$3::uuid`, message.Tenant, message.Connector, message.CommandID).Scan(&request, &admission, &contextDigest, &mutationDigest, &authorized, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if admission != message.Observation.AdmissionUID || string(contextDigest) != string(message.Observation.ContextDigest[:]) || string(mutationDigest) != string(receipt.MutationDigest[:]) || message.AppliedAt.Before(authorized) || message.AppliedAt.After(expires) {
		return false, nil
	}
	c, err := s.Store.ChangeWithin(ctx, tx, message.Tenant, request)
	if err != nil {
		return false, err
	}
	return c.ExecutionID == message.CommandID && (c.State == domain.Executing || c.State == domain.Executed) && c.Intent.Kubernetes != nil && c.Intent.Kubernetes.SourceDigest.String() == receipt.BeforeDigest && c.Intent.Kubernetes.MutationDigest == receipt.MutationDigest && c.CorrelationID == message.CorrelationID, nil
}
