package workflow

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type KubernetesSubmit struct {
	Mutation        kube.Mutation
	Justification   string
	CommandID       uuid.UUID
	CorrelationID   string
	MinGraphVersion int64
}

type nativePrivateContext struct {
	Version       int           `json:"native_context_version"`
	Justification string        `json:"justification"`
	Mutation      kube.Mutation `json:"mutation"`
}

// KubernetesPlan retains anonymous authority projections only. Their digest is
// committed in the ordinary change intent; raw object/identity facts are sealed
// separately and are not copied into append-only lifecycle events.
type KubernetesPlan struct {
	legacyEncoding   bool
	Version          int          `json:"version"`
	Tenant           string       `json:"tenant_id"`
	Request          string       `json:"request_id"`
	Connector        string       `json:"connector_id"`
	SourceKey        string       `json:"source_key"`
	SourceRevision   int64        `json:"source_revision"`
	SourceDigest     ports.Digest `json:"source_digest"`
	MutationDigest   ports.Digest `json:"mutation_digest"`
	ObjectKey        string       `json:"object_key"`
	Operation        string       `json:"operation"`
	PrivateReference string       `json:"private_record_reference"`
	PrivateDigest    ports.Digest `json:"private_content_digest"`
	Current          graph.Data   `json:"current_projection"`
	Before           graph.Data   `json:"before_projection"`
	After            graph.Data   `json:"after_projection"`
}

func NativeObjectKey(m kube.Mutation) string {
	o := m.After
	if o == nil {
		o = m.Before
	}
	if o == nil {
		return ""
	}
	return graph.KubernetesNodeID(m.Cluster, "object", kube.ObjectKey(*o))
}

func anonymousNative(data graph.Data) bool {
	if len(data.Kubernetes) != 0 || len(data.KubernetesDigests) != 0 {
		return false
	}
	for _, n := range data.Nodes {
		if !strings.HasPrefix(n.ID, "k8s:") || n.DisplayName != "" || len(n.Properties) != 0 {
			return false
		}
	}
	for _, e := range data.Edges {
		if !strings.HasPrefix(e.ID, "k8s:") || len(e.Properties) != 0 {
			return false
		}
	}
	return true
}

func nativeAssociations(snapshot *graph.Snapshot, active *policy.Active, current graph.Data) (*graph.Snapshot, error) {
	bindings, ok := active.Data()["kubernetes_identity_bindings"].(map[string]any)
	if !ok || len(bindings) > 2048 {
		return nil, ErrDependency
	}
	data := snapshot.Data()
	seen := map[string]graph.Edge{}
	for _, e := range data.Edges {
		seen[e.ID] = e
	}
	for _, n := range current.Nodes {
		if !graph.Identity(n.Type) {
			continue
		}
		value, exists := bindings[n.ID]
		if !exists {
			if n.Type == "Human" {
				return nil, ErrDependency
			}
			continue
		}
		actor, valid := value.(string)
		if !valid {
			return nil, ErrDependency
		}
		if actor == "" {
			continue
		}
		core, err := snapshot.Node(actor)
		if err != nil || core.Type != "Human" || core.Properties["disabled"] == "true" || strings.HasPrefix(actor, "k8s:") {
			return nil, ErrDependency
		}
		edge := graph.Edge{ID: graph.KubernetesNodeID("core-association", "edge", actor+"\x00"+n.ID), Source: actor, Target: n.ID, Kind: "CAN_ASSUME"}
		if old, exists := seen[edge.ID]; exists {
			if !reflect.DeepEqual(old, edge) {
				return nil, ErrDependency
			}
			continue
		}
		data.Edges = append(data.Edges, edge)
	}
	return graph.Build(snapshot.Version(), data)
}

func nativeProjection(snapshot *graph.Snapshot, active *policy.Active, plan KubernetesPlan) (*graph.Snapshot, graph.Impact, graph.Delta, error) {
	if !anonymousNative(plan.Current) || !anonymousNative(plan.Before) || !anonymousNative(plan.After) {
		return nil, graph.Impact{}, graph.Delta{}, eventstore.ErrIntegrity
	}
	if snapshot.Data().KubernetesDigests[plan.SourceKey] != plan.SourceDigest.String() {
		return nil, graph.Impact{}, graph.Delta{}, domain.ErrContextChanged
	}
	view, err := nativeAssociations(snapshot, active, plan.Current)
	if err != nil {
		return nil, graph.Impact{}, graph.Delta{}, err
	}
	before, _, impact, delta, err := view.KubernetesProjection(plan.Current, plan.Before, plan.After)
	return before, impact, delta, err
}

func (s *Service) nativePlanWithin(ctx context.Context, tx pgx.Tx, c domain.Change) (KubernetesPlan, error) {
	var plan KubernetesPlan
	n := c.Intent.Kubernetes
	if n == nil || n.PlanID != c.ID {
		return plan, domain.ErrInvalid
	}
	var raw, hash []byte
	var position int64
	if err := tx.QueryRow(ctx, `SELECT document,plan_digest,event_position FROM ratchet.native_change_plans WHERE tenant_id=$1 AND request_id=$2::uuid`, c.TenantID, c.ID).Scan(&raw, &hash, &position); err != nil {
		return plan, err
	}
	if json.Unmarshal(raw, &plan) != nil {
		return plan, eventstore.ErrIntegrity
	}
	digest, err := canon.New().Digest(plan)
	if err != nil || digest != n.PlanDigest || string(hash) != string(digest[:]) || plan.Version != 1 || plan.Tenant != c.TenantID || plan.Request != c.ID || plan.Connector != n.Connector || plan.SourceKey != n.SourceKey || plan.SourceDigest != n.SourceDigest || plan.MutationDigest != n.MutationDigest || plan.ObjectKey != c.Intent.Target || plan.Operation != n.Operation || plan.PrivateReference != n.PrivateReference || plan.PrivateDigest != n.PrivateDigest {
		return plan, eventstore.ErrIntegrity
	}
	events, err := s.Store.StreamWithin(ctx, tx, c.TenantID, "native-plan:"+c.ID)
	if err != nil {
		return plan, err
	}
	if len(events) != 1 || events[0].Sequence != position || events[0].Type != "KubernetesPlanRecorded" {
		return plan, eventstore.ErrIntegrity
	}
	var content ledger.Content
	var payload struct {
		Facts struct {
			PlanDigest ports.Digest `json:"plan_digest"`
		} `json:"facts"`
	}
	if json.Unmarshal(events[0].Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil || payload.Facts.PlanDigest != digest {
		return plan, eventstore.ErrIntegrity
	}
	return plan, nil
}

func (s *Service) nativeMutationWithin(ctx context.Context, tx pgx.Tx, c domain.Change) (nativePrivateContext, error) {
	var out nativePrivateContext
	n := c.Intent.Kubernetes
	if n == nil {
		return out, domain.ErrInvalid
	}
	raw, err := s.Store.PrivateWithin(ctx, tx, c.TenantID, n.PrivateReference, s.key)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || out.Version != 1 || out.Mutation.Validate() != nil {
		return out, eventstore.ErrIntegrity
	}
	digest, err := canon.New().Digest(out)
	if err != nil || digest != n.PrivateDigest {
		return out, eventstore.ErrIntegrity
	}
	mutation, err := canon.New().Digest(out.Mutation)
	if err != nil || mutation != n.MutationDigest {
		return out, eventstore.ErrIntegrity
	}
	return out, nil
}

func (s *Service) changeImpactWithin(ctx context.Context, tx pgx.Tx, snapshot *graph.Snapshot, active *policy.Active, c domain.Change) (*graph.Snapshot, graph.Impact, graph.Delta, error) {
	if c.Intent.Kubernetes == nil {
		result, delta, err := impact(snapshot, c.Intent)
		return snapshot, result, delta, err
	}
	plan, err := s.nativePlanWithin(ctx, tx, c)
	if err != nil {
		return nil, graph.Impact{}, graph.Delta{}, err
	}
	private, err := s.nativeMutationWithin(ctx, tx, c)
	if err != nil {
		return nil, graph.Impact{}, graph.Delta{}, err
	}
	state, revision, err := s.Store.KubernetesSourceWithin(ctx, tx, c.TenantID, plan.Connector, plan.SourceKey, s.key)
	if err != nil {
		return nil, graph.Impact{}, graph.Delta{}, err
	}
	digest, err := graph.KubernetesStateDigest(state)
	if err != nil || digest != plan.SourceDigest.String() || revision != plan.SourceRevision {
		return nil, graph.Impact{}, graph.Delta{}, domain.ErrContextChanged
	}
	if _, err := state.After(private.Mutation); err != nil {
		return nil, graph.Impact{}, graph.Delta{}, err
	}
	return nativeProjection(snapshot, active, plan)
}

func (s *Service) SubmitKubernetes(ctx context.Context, actor Actor, input KubernetesSubmit) (out domain.Change, err error) {
	if input.Mutation.Validate() != nil || input.CommandID == uuid.Nil || len(strings.TrimSpace(input.Justification)) < 10 || len(input.Justification) > 4000 || input.MinGraphVersion < 0 || input.MinGraphVersion > ledger.MaxSafeInteger {
		return out, domain.ErrInvalid
	}
	if input.CorrelationID == "" {
		input.CorrelationID = input.CommandID.String()
	}
	if id, e := uuid.Parse(input.CorrelationID); e != nil || id == uuid.Nil {
		return out, domain.ErrInvalid
	}
	privateBody := nativePrivateContext{Version: 1, Justification: input.Justification, Mutation: input.Mutation}
	privateDigest, err := canon.New().Digest(privateBody)
	if err != nil {
		return out, err
	}
	mutationDigest, err := canon.New().Digest(input.Mutation)
	if err != nil {
		return out, err
	}
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+input.CommandID.String())).String()
	recordID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(requestID+":"+privateDigest.String()))
	raw, err := json.Marshal(privateBody)
	if err != nil {
		return out, err
	}
	private, err := eventstore.SealPrivate(s.key, actor.TenantID, recordID, "native-workflow-v1", raw)
	if err != nil {
		return out, err
	}
	inputDigest, err := canon.New().Digest(struct {
		Actor Actor
		Input KubernetesSubmit
	}{actor, input})
	if err != nil {
		return out, err
	}
	err = s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		var plan KubernetesPlan
		var planDigest ports.Digest
		mutation := eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: requestID, ID: input.CommandID, InputDigest: inputDigest, Private: &private}
		mutation.Additional = func(tx pgx.Tx, _ eventstore.Receipt) error {
			facts, e := json.Marshal(struct {
				PlanDigest     ports.Digest `json:"plan_digest"`
				SourceDigest   ports.Digest `json:"source_digest"`
				MutationDigest ports.Digest `json:"mutation_digest"`
			}{planDigest, plan.SourceDigest, plan.MutationDigest})
			if e != nil {
				return e
			}
			r, e := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: uuid.NewSHA1(input.CommandID, []byte("native-plan")), ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), StreamID: "native-plan:" + requestID, Events: []eventstore.Event{{Type: "KubernetesPlanRecorded", Facts: facts}}})
			if e != nil {
				return e
			}
			document, e := json.Marshal(plan)
			if e != nil {
				return e
			}
			_, e = tx.Exec(ctx, `INSERT INTO ratchet.native_change_plans(tenant_id,request_id,plan_digest,document,event_position) VALUES($1,$2,$3,$4,$5)`, actor.TenantID, requestID, planDigest.Bytes(), document, r.LastSequence)
			return e
		}
		var e error
		out, e = s.Store.MutateChangeWithin(ctx, tx, now, mutation, func(tx pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
			snapshot, active, e := s.context(ctx, tx, actor, "submit", nil)
			if e != nil {
				return nil, e
			}
			if snapshot.Version() < input.MinGraphVersion {
				return nil, graph.ErrUnavailable
			}
			key := graph.KubernetesSourceKey(input.Mutation.Cluster)
			state, revision, e := s.Store.KubernetesSourceWithin(ctx, tx, actor.TenantID, input.Mutation.Connector, key, s.key)
			if e != nil {
				return nil, e
			}
			after, e := state.After(input.Mutation)
			if e != nil {
				return nil, e
			}
			baseline, e := graph.CompileKubernetes(snapshot.Version(), state)
			if e != nil {
				return nil, e
			}
			beforeCommon, e := graph.CompileKubernetes(snapshot.Version(), state, after)
			if e != nil {
				return nil, e
			}
			afterCommon, e := graph.CompileKubernetes(snapshot.Version(), after, state)
			if e != nil {
				return nil, e
			}
			sourceDigest, e := graph.KubernetesStateDigest(state)
			if e != nil {
				return nil, e
			}
			source, e := ports.DigestFromHex(sourceDigest)
			if e != nil {
				return nil, e
			}
			plan = KubernetesPlan{Version: 1, Tenant: actor.TenantID, Request: requestID, Connector: input.Mutation.Connector, SourceKey: key, SourceRevision: revision, SourceDigest: source, MutationDigest: mutationDigest, ObjectKey: NativeObjectKey(input.Mutation), Operation: input.Mutation.Operation, PrivateReference: recordID.String(), PrivateDigest: privateDigest, Current: baseline.Data(), Before: beforeCommon.Data(), After: afterCommon.Data()}
			if _, _, _, e := nativeProjection(snapshot, active, plan); e != nil {
				return nil, e
			}
			planDigest, e = canon.New().Digest(plan)
			if e != nil {
				return nil, e
			}
			intent := domain.Intent{Kind: "K8S_RBAC_CHANGE", Target: plan.ObjectKey, Access: plan.Operation, Kubernetes: &domain.KubernetesChange{PlanID: requestID, PlanDigest: planDigest, MutationDigest: mutationDigest, SourceDigest: source, SourceKey: key, Connector: plan.Connector, Operation: plan.Operation, PrivateReference: recordID.String(), PrivateDigest: privateDigest}}
			events, e := domain.Decide(current, domain.Command{Kind: "SUBMIT", At: now, Submission: &domain.Change{ID: requestID, CorrelationID: input.CorrelationID, TenantID: actor.TenantID, Requester: actor.ID, Intent: intent, PrivateReference: recordID.String(), PrivateDigest: privateDigest}})
			if e != nil {
				return nil, e
			}
			if e := s.enqueue(ctx, tx, JobArgs{actor.TenantID, requestID, 1, "assess"}); e != nil {
				return nil, e
			}
			return events, nil
		})
		return e
	})
	return out, err
}

func (s *Service) KubernetesContext(ctx context.Context, actor Actor, c domain.Change) (kube.Mutation, error) {
	var out kube.Mutation
	if c.Intent.Kubernetes == nil {
		return out, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		if actor.TenantID != c.TenantID {
			return ErrPermission
		}
		actual, err := s.Store.ChangeWithin(ctx, tx, c.TenantID, c.ID)
		if err != nil {
			return err
		}
		c = actual
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		if actor.ID != c.Requester {
			detail, err := s.visibility(ctx, tx, actor, c, snapshot, active)
			if err != nil {
				return err
			}
			if !detail {
				return ErrPermission
			}
		}
		value, err := s.nativeMutationWithin(ctx, tx, c)
		if err != nil {
			return err
		}
		out = value.Mutation
		facts, _ := json.Marshal(map[string]string{"request_id": c.ID, "operation": "native_context_read"})
		_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: c.TenantID, ID: uuid.New(), ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(c.TenantID+":"+actor.ID)), StreamID: "sensitive-access:" + c.ID, Events: []eventstore.Event{{Type: "SensitiveRecordRead", Facts: facts}}})
		return err
	})
	return out, err
}
