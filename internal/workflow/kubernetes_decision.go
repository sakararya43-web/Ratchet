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
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// KubernetesDecision retains commitments and the core actor reference. Native
// UserInfo, target names, subjects and the exact mutation are encrypted separately.
type KubernetesDecision struct {
	ID                  string          `json:"decision_id"`
	Tenant              string          `json:"tenant_id"`
	Connector           string          `json:"connector_id"`
	AdmissionUID        string          `json:"admission_uid"`
	RequestID           string          `json:"request_id"`
	CommandID           string          `json:"command_id"`
	Actor               string          `json:"actor_id"`
	ContextDigest       ports.Digest    `json:"context_digest"`
	MutationDigest      ports.Digest    `json:"mutation_digest"`
	ObjectDigest        ports.Digest    `json:"object_digest"`
	Decision            domain.Decision `json:"decision"`
	PolicyOutcome       string          `json:"policy_outcome"`
	GraphVersion        int64           `json:"graph_version"`
	PolicyDigest        ports.Digest    `json:"policy_digest"`
	RegistryDigest      ports.Digest    `json:"registry_digest"`
	RegistryEpoch       int64           `json:"registry_epoch"`
	ExecutionAuthorized bool            `json:"execution_authorized"`
	At                  time.Time       `json:"at"`
	ExpiresAt           time.Time       `json:"expires_at"`
	Signature           []byte          `json:"signature,omitempty"`
}

func KubernetesDecisionSigningDigest(out KubernetesDecision) (ports.Digest, error) {
	out.Signature = nil
	return signingDigest("RATCHET_KUBERNETES_DECISION_V1", out)
}

func (s *Service) kubernetesPin(a kube.Admission) (kube.KubernetesConnectorKey, error) {
	for _, pin := range s.config.KubernetesConnectors {
		if pin.Tenant == a.Tenant && pin.Connector == a.Mutation.Connector && pin.Cluster == a.Mutation.Cluster {
			return pin, nil
		}
	}
	return kube.KubernetesConnectorKey{}, ErrPermission
}

// DecideKubernetes consumes an already staged command in the same tenant
// transaction as the retained decision. It cannot submit or dispatch a change,
// and it never treats an admission response as target read-back verification.
func (s *Service) DecideKubernetes(ctx context.Context, message kube.SignedKubernetesAdmission) (out KubernetesDecision, err error) {
	pin, err := s.kubernetesPin(message.Admission)
	if err != nil {
		return out, err
	}
	if _, err := kube.VerifyKubernetesAdmission(canon.New(), pin, message, time.Now().UTC()); err != nil {
		return out, err
	}
	ctx, span := s.observer.Start(ctx, "inline_decision", pin.Tenant, message.Admission.AdmissionUID)
	defer func() { span.End(err) }()
	err = s.Store.WithTenantTx(ctx, pin.Tenant, func(tx pgx.Tx, now time.Time) error {
		a, err := kube.VerifyKubernetesAdmission(canon.New(), pin, message, now)
		if err != nil {
			return err
		}
		contextDigest, err := canon.New().Digest(a)
		if err != nil {
			return err
		}
		id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(pin.Tenant+":native-admission:"+pin.Connector+":"+a.AdmissionUID))
		stream := "native-admission:" + id.String()
		prior, err := s.Store.StreamWithin(ctx, tx, pin.Tenant, stream)
		if err != nil {
			return err
		}
		if len(prior) > 0 {
			var content ledger.Content
			var payload struct {
				Facts KubernetesDecision `json:"facts"`
			}
			if len(prior) != 1 || prior[0].Type != "KubernetesDecisionRecorded" || json.Unmarshal(prior[0].Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil || payload.Facts.ID != id.String() {
				return eventstore.ErrIntegrity
			}
			out = payload.Facts
			if out.ContextDigest != contextDigest {
				return eventstore.ErrIdempotencyConflict
			}
			// Never return a reusable signed permit, including after process restart.
			out.Signature, out.ExecutionAuthorized, out.ExpiresAt = nil, false, time.Time{}
			out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"admission already evaluated; reconcile the original command"}}
			return nil
		}
		mutationDigest, err := canon.New().Digest(a.Mutation)
		if err != nil {
			return err
		}
		out = KubernetesDecision{ID: id.String(), Tenant: pin.Tenant, Connector: pin.Connector, AdmissionUID: a.AdmissionUID, RequestID: a.ApprovedRequestID, CommandID: a.CommandID, ContextDigest: contextDigest, MutationDigest: mutationDigest, ObjectDigest: a.Mutation.ObjectDigest, At: now, Decision: domain.Decision{Outcome: "HOLD", Reasons: []string{"current exact approved execution binding required"}}}
		if err := s.evaluateKubernetesAdmission(ctx, tx, now, pin, a, message.ExpiresAt, &out); err != nil {
			return err
		}
		privateRaw, err := json.Marshal(message)
		if err != nil {
			return err
		}
		private, err := eventstore.SealPrivate(s.key, pin.Tenant, uuid.NewSHA1(id, []byte("native-admission-context")), "native-admission-v1", privateRaw)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: pin.Tenant, ID: id, StreamID: stream, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(pin.Tenant+":connector:"+pin.Connector)), Events: []eventstore.Event{{Type: "KubernetesDecisionRecorded", Facts: raw, Private: &private}}})
		return err
	})
	return out, err
}

func (s *Service) evaluateKubernetesAdmission(ctx context.Context, tx pgx.Tx, now time.Time, pin kube.KubernetesConnectorKey, a kube.Admission, expires time.Time, out *KubernetesDecision) error {
	state, sourceRevision, err := s.Store.KubernetesSourceWithin(ctx, tx, pin.Tenant, pin.Connector, graph.KubernetesSourceKey(pin.Cluster), s.key)
	if err != nil {
		return ErrDependency
	}
	principal, err := a.PrincipalIn(state)
	if err != nil {
		out.Decision.Reasons = []string{"admission identity, target preimage or source cut is stale or unsupported"}
		return nil
	}
	active, err := s.active(ctx, tx, pin.Tenant)
	if err != nil {
		return ErrDependency
	}
	bindings, ok := active.Data()["kubernetes_identity_bindings"].(map[string]any)
	if !ok {
		return ErrDependency
	}
	actorID, ok := bindings[graph.KubernetesNodeID(state.Cluster, "identity", principal.ID)].(string)
	if !ok || actorID == "" {
		return ErrPermission
	}
	actor := Actor{TenantID: pin.Tenant, ID: actorID}
	if a.ApprovedRequestID == "" {
		// No policy result can authorize an unstaged native write. Refuse this
		// missing prerequisite before rebuilding an unsolicited proposal; full
		// impact assessment belongs to submission and authenticated drift intake.
		out.Actor, out.PolicyDigest, out.RegistryDigest, out.RegistryEpoch = actorID, active.Hash, active.RegistryDigest, active.RegistryEpoch
		out.PolicyOutcome = "NOT_EVALUATED_NO_GUARDED_COMMAND"
		out.Decision = domain.Decision{Outcome: "HOLD", Reasons: []string{"a guarded independently approved command is required for native execution"}}
		return nil
	}
	// Every source advance receives a new tenant ledger position. Under this
	// tenant lock, an equal healthy position preserves Guard's complete graph
	// proof; loading and rebuilding the graph adds no new authorization facts.
	var graphVersion int64
	var quarantined bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(graph_version),0),COALESCE(bool_or(needs_resync),false) FROM ratchet.graph_sources WHERE tenant_id=$1`, pin.Tenant).Scan(&graphVersion, &quarantined); err != nil {
		return err
	}
	if quarantined || graphVersion < 1 {
		return ErrDependency
	}
	out.Actor, out.GraphVersion, out.PolicyDigest, out.RegistryDigest, out.RegistryEpoch = actorID, graphVersion, active.Hash, active.RegistryDigest, active.RegistryEpoch
	if graphVersion < a.MinGraphVersion {
		out.Decision.Reasons = []string{"graph has not reached the requested version"}
		return nil
	}
	c, err := s.Store.ChangeWithin(ctx, tx, pin.Tenant, a.ApprovedRequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	n := c.Intent.Kubernetes
	if n == nil || n.MutationDigest != out.MutationDigest || n.Connector != pin.Connector || c.Intent.Target != NativeObjectKey(a.Mutation) || c.Requester != actorID {
		return nil
	}
	command, err := s.nativeAuthorization(ctx, tx, now, actor, a, graphVersion, active, c, state, sourceRevision)
	if err != nil || command == nil {
		return err
	}
	out.PolicyOutcome = c.Decision.Outcome
	if a.DryRun {
		out.Decision.Reasons = []string{"dry-run does not consume an execution permit"}
		return nil
	}
	if command.Deadline.Before(expires) {
		expires = command.Deadline
	}
	if now.Add(5 * time.Second).Before(expires) {
		expires = now.Add(5 * time.Second)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ratchet.native_admissions(tenant_id,connector_id,command_id,request_id,admission_uid,context_digest,mutation_digest,authorized_at,expires_at) VALUES($1,$2,$3::uuid,$4::uuid,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, pin.Tenant, pin.Connector, a.CommandID, a.ApprovedRequestID, a.AdmissionUID, out.ContextDigest.Bytes(), out.MutationDigest.Bytes(), now, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		out.Decision.Reasons = []string{"command already consumed by an admission"}
		return nil
	}
	out.ExecutionAuthorized, out.ExpiresAt = true, expires
	out.Decision = domain.Decision{Outcome: "ALLOW", Reasons: []string{"exact independently approved native command consumed for this admission"}}
	digest, err := KubernetesDecisionSigningDigest(*out)
	if err != nil {
		return err
	}
	out.Signature = ed25519.Sign(s.executions[pin.Tenant].private, digest[:])
	return nil
}

func ephemeralKubernetesPlan(state kube.State, mutation kube.Mutation) (KubernetesPlan, error) {
	after, err := state.After(mutation)
	if err != nil {
		return KubernetesPlan{}, err
	}
	current, err := graph.CompileKubernetes(0, state)
	if err != nil {
		return KubernetesPlan{}, err
	}
	before, err := graph.CompileKubernetes(0, state, after)
	if err != nil {
		return KubernetesPlan{}, err
	}
	next, err := graph.CompileKubernetes(0, after, state)
	if err != nil {
		return KubernetesPlan{}, err
	}
	digest, err := graph.KubernetesStateDigest(state)
	if err != nil {
		return KubernetesPlan{}, err
	}
	hash, err := ports.DigestFromHex(digest)
	return KubernetesPlan{SourceKey: graph.KubernetesSourceKey(state.Cluster), SourceDigest: hash, Current: current.Data(), Before: before.Data(), After: next.Data()}, err
}

func (s *Service) nativeAuthorization(ctx context.Context, tx pgx.Tx, now time.Time, actor Actor, a kube.Admission, graphVersion int64, active *policy.Active, c domain.Change, state kube.State, sourceRevision int64) (*PreparedCommand, error) {
	if c.State != domain.Executing || c.ExecutionID != a.CommandID || c.Envelope == nil || c.Envelope.GraphVersion != graphVersion || c.Envelope.PolicyDigest != active.Hash || c.Envelope.RegistryDigest != active.RegistryDigest || c.Envelope.RegistryEpoch != active.RegistryEpoch || !now.Before(c.Envelope.ExpiresAt) {
		return nil, nil
	}
	// The signed staged command is issued only by Guard after full policy,
	// impact and independence proof. Exact unchanged graph/policy/registry and
	// source commitments preserve that proof; do not rebuild its graph inline.
	if c.Decision.Outcome != "ALLOW" && c.Decision.Outcome != "REQUIRE_APPROVAL" || s.approvals == nil || len(c.Approvals) < max(1, c.Decision.Quorum) {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, approval := range c.Approvals {
		if approval.ActorID == c.Requester || seen[approval.ActorID] {
			return nil, nil
		}
		verified, err := s.approvals.Verify(ctx, approval.Evidence, c.Digest)
		if err != nil || !verified.UserVerified || verified.ActorID != approval.ActorID || verified.TenantID != c.TenantID || verified.ChangeDigest != c.Digest || !slices.Equal(verified.CredentialID, approval.CredentialID) {
			return nil, nil
		}
		seen[approval.ActorID] = true
	}
	e := s.executions[actor.TenantID]
	if e == nil || e.Connector != a.Mutation.Connector || !e.capability.NativeRBAC || !now.Before(e.capability.Expires) {
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
	n := command.Kubernetes
	if n == nil || command.VerifyOnly || command.Purpose != "KUBERNETES_ADMISSION" || command.CommandID != a.CommandID || command.RequestID != c.ID || command.Tenant != c.TenantID || command.Connector != e.Connector || command.EnvelopeDigest != c.Digest || !now.Before(command.Deadline) || n.PlanDigest != c.Intent.Kubernetes.PlanDigest || n.MutationDigest != c.Intent.Kubernetes.MutationDigest || n.SourceDigest != c.Intent.Kubernetes.SourceDigest || n.SourceResourceVersion != a.SourceResourceVersion || n.ObjectKey != NativeObjectKey(a.Mutation) || n.Operation != a.Mutation.Operation {
		return nil, nil
	}
	if a.Mutation.Before != nil && (n.ExpectedUID != a.Mutation.Before.UID || n.ExpectedResourceVersion != a.Mutation.Before.ResourceVersion) {
		return nil, nil
	}
	source, err := graph.KubernetesStateDigest(state)
	if err != nil || source != n.SourceDigest.String() || command.ExpectedRevision != sourceRevision {
		return nil, nil
	}
	if command.Envelope == nil {
		return nil, eventstore.ErrIntegrity
	}
	envelope, err := canon.New().Digest(command.Envelope)
	if err != nil || envelope != c.Digest {
		return nil, eventstore.ErrIntegrity
	}
	wantApprovals, err := canon.New().Digest(c.Approvals)
	if err != nil {
		return nil, err
	}
	stagedApprovals, err := canon.New().Digest(command.Approvals)
	if err != nil || wantApprovals != stagedApprovals {
		return nil, eventstore.ErrIntegrity
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
