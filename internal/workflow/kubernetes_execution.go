package workflow

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/google/uuid"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

// NativeCommandBinding commits to the exact private mutation without retaining
// native names or subjects in the durable command/outbox. The connector submits
// the real admission object to consume this command; this is not a write API.
type NativeCommandBinding struct {
	PlanDigest              ports.Digest `json:"plan_digest"`
	MutationDigest          ports.Digest `json:"mutation_digest"`
	SourceDigest            ports.Digest `json:"source_digest"`
	SourceResourceVersion   string       `json:"source_resource_version"`
	ObjectKey               string       `json:"object_key"`
	Operation               string       `json:"operation"`
	ExpectedUID             string       `json:"expected_uid"`
	ExpectedResourceVersion string       `json:"expected_resource_version"`
}

func (s *Service) configureKubernetes(pins []kube.KubernetesConnectorKey) error {
	s.config.KubernetesConnectors = make([]kube.KubernetesConnectorKey, 0, len(pins))
	seen := map[string]bool{}
	for _, pin := range pins {
		id := pin.Tenant + "\x00" + pin.Connector + "\x00" + pin.Cluster
		if !s.tenants[pin.Tenant] || pin.Connector == "" || pin.Cluster == "" || len(pin.PublicKey) != ed25519.PublicKeySize || seen[id] {
			return domain.ErrInvalid
		}
		if e := s.executions[pin.Tenant]; e != nil && e.Connector == pin.Connector && !slices.Equal(e.public, pin.PublicKey) {
			return domain.ErrInvalid
		}
		seen[id] = true
		pin.PublicKey = slices.Clone(pin.PublicKey)
		s.config.KubernetesConnectors = append(s.config.KubernetesConnectors, pin)
	}
	return nil
}

func (s *Service) prepareKubernetes(ctx context.Context, tx pgx.Tx, c domain.Change, id string, now time.Time) (PreparedCommand, error) {
	var command PreparedCommand
	e := s.executions[c.TenantID]
	n := c.Intent.Kubernetes
	if e == nil || n == nil || e.Connector != n.Connector || !e.capability.NativeRBAC || !now.Before(e.capability.Expires) || e.capability.Expires.After(now.Add(24*time.Hour)) || c.Envelope == nil {
		return command, ErrDependency
	}
	plan, err := s.nativePlanWithin(ctx, tx, c)
	if err != nil {
		return command, err
	}
	private, err := s.nativeMutationWithin(ctx, tx, c)
	if err != nil {
		return command, err
	}
	state, revision, err := s.Store.KubernetesSourceWithin(ctx, tx, c.TenantID, e.Connector, n.SourceKey, s.key)
	if err != nil {
		return command, err
	}
	if revision != plan.SourceRevision {
		return command, domain.ErrContextChanged
	}
	if _, err := s.kubernetesPin(kube.Admission{Tenant: c.TenantID, Mutation: private.Mutation}); err != nil {
		return command, ErrDependency
	}
	binding := &NativeCommandBinding{PlanDigest: n.PlanDigest, MutationDigest: n.MutationDigest, SourceDigest: n.SourceDigest, SourceResourceVersion: state.ResourceVersion, ObjectKey: c.Intent.Target, Operation: n.Operation}
	if private.Mutation.Before != nil {
		binding.ExpectedUID = private.Mutation.Before.UID
		binding.ExpectedResourceVersion = private.Mutation.Before.ResourceVersion
	}
	correlation := c.CorrelationID
	if correlation == "" {
		correlation = c.ID
	}
	command = PreparedCommand{SchemaVersion: 1, Tenant: c.TenantID, Connector: e.Connector, MessageID: id, CommandID: id, RequestID: c.ID, CorrelationID: correlation, ExpectedRevision: revision, ExpectedRoles: []string{}, BeforeRoles: []string{}, Envelope: c.Envelope, EnvelopeDigest: c.Digest, Approvals: c.Approvals, Deadline: c.Envelope.ExpiresAt, DispatchedAt: now, Purpose: "KUBERNETES_ADMISSION", Kubernetes: binding, TraceParent: telemetry.Parent(ctx)}
	digest, err := signingDigest("RATCHET_EXEC_COMMAND_V1", command)
	if err != nil {
		return command, err
	}
	command.Signature = ed25519.Sign(e.private, digest[:])
	return command, nil
}

type NativeObservation struct {
	AdmissionUID  string       `json:"admission_uid"`
	ContextDigest ports.Digest `json:"context_digest"`
	Object        *kube.Object `json:"object"`
	DeletedUID    string       `json:"deleted_uid"`
}

func NativeObservationDigest(r ExecutionResult) (ports.Digest, error) {
	return canon.New().Digest(struct {
		Tenant      string             `json:"tenant_id"`
		Target      string             `json:"target"`
		Revision    int64              `json:"source_revision"`
		At          time.Time          `json:"observed_at"`
		Observation *NativeObservation `json:"observation"`
	}{r.ObservedTenant, r.ObservedTarget, r.ObservedRevision, r.ObservedAt, r.Kubernetes})
}

// nativeExecutionResult requires a connector-authenticated independent read-back
// of the exact security object. Kubernetes resourceVersion remains opaque; it is
// not a numeric source revision and is never assumed to increment by one.
func (s *Service) nativeExecutionResult(ctx context.Context, tx pgx.Tx, now time.Time, c domain.Change, command PreparedCommand, r ExecutionResult, signedDigest ports.Digest) ([]domain.Event, error) {
	if c.Intent.Kubernetes == nil || r.Kubernetes == nil || command.Purpose != "KUBERNETES_ADMISSION" {
		return nil, ErrPermission
	}
	var events []domain.Event
	var err error
	if !r.ReadBackVerified {
		events, err = domain.Decide(c, domain.Command{Kind: "RECONCILE", At: now, ExecutionID: c.ExecutionID})
		if err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, JobArgs{c.TenantID, c.ID, c.Revision + 1, "reconcile"}); err != nil {
			return nil, err
		}
	} else {
		if r.ObservedTenant != c.TenantID || r.ObservedTarget != c.Intent.Target || r.ObservedRevision < command.ExpectedRevision || r.ObservedRevision > 1<<53-1 || r.ObservedAt.Before(command.DispatchedAt) || r.ObservedAt.After(now.Add(time.Minute)) || len(r.ObservedRoles) != 0 {
			return nil, ErrPermission
		}
		digest, err := NativeObservationDigest(r)
		if err != nil || digest != r.ObservationDigest {
			return nil, ErrPermission
		}
		private, err := s.nativeMutationWithin(ctx, tx, c)
		if err != nil {
			return nil, err
		}
		mutation, observed := private.Mutation, r.Kubernetes
		if observed.Object != nil && (observed.Object.Validate() != nil || observed.Object.UID == "" || observed.Object.ResourceVersion == "") {
			return nil, ErrPermission
		}
		if r.Success {
			var uid string
			var contextDigest, mutationDigest []byte
			var authorized, expires time.Time
			if err := tx.QueryRow(ctx, `SELECT admission_uid,context_digest,mutation_digest,authorized_at,expires_at FROM ratchet.native_admissions WHERE tenant_id=$1 AND connector_id=$2 AND command_id=$3::uuid AND request_id=$4::uuid`, c.TenantID, command.Connector, command.CommandID, c.ID).Scan(&uid, &contextDigest, &mutationDigest, &authorized, &expires); err != nil {
				return nil, ErrPermission
			}
			if observed.AdmissionUID != uid || string(contextDigest) != string(observed.ContextDigest[:]) || string(mutationDigest) != string(command.Kubernetes.MutationDigest[:]) || !applicationTimeValid(command, r) || r.AppliedAt.Before(authorized) || r.AppliedAt.After(expires) {
				return nil, ErrPermission
			}
			id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(c.TenantID+":native-admission:"+command.Connector+":"+uid))
			private, err := s.Store.PrivateWithin(ctx, tx, c.TenantID, uuid.NewSHA1(id, []byte("native-admission-context")).String(), s.key)
			if err != nil {
				return nil, err
			}
			var admitted kube.SignedKubernetesAdmission
			if json.Unmarshal(private, &admitted) != nil {
				return nil, eventstore.ErrIntegrity
			}
			bound, err := canon.New().Digest(admitted.Admission)
			if err != nil || string(bound[:]) != string(contextDigest) {
				return nil, eventstore.ErrIntegrity
			}
			if admitted.Admission.CreateUID != "" && (observed.Object == nil || observed.Object.UID != admitted.Admission.CreateUID) {
				return nil, ErrPermission
			}
			if mutation.Operation == "DELETE" {
				if observed.Object != nil || observed.DeletedUID != mutation.Before.UID {
					return nil, ErrPermission
				}
			} else {
				if observed.Object == nil || observed.DeletedUID != "" {
					return nil, ErrPermission
				}
				if mutation.Before != nil && (observed.Object.UID != mutation.Before.UID || observed.Object.ResourceVersion == mutation.Before.ResourceVersion) {
					return nil, ErrPermission
				}
				want, got := *mutation.After, *observed.Object
				want.UID, want.ResourceVersion, got.UID, got.ResourceVersion = "", "", "", ""
				if !sameNativeObject(&want, &got) {
					return nil, ErrPermission
				}
			}
			events, err = domain.Decide(c, domain.Command{Kind: "VERIFIED", At: now, ExecutionID: c.ExecutionID, Verified: true})
		} else {
			if !r.AppliedAt.IsZero() || observed.DeletedUID != "" || !sameNativeObject(mutation.Before, observed.Object) {
				return nil, ErrPermission
			}
			events, err = domain.Decide(c, domain.Command{Kind: "EXECUTION_FAILED", At: now, ExecutionID: c.ExecutionID, Reason: "native connector refused change; unchanged target independently observed"})
		}
		if err != nil {
			return nil, err
		}
	}
	// The signed raw result is a separate encrypted record. Retained facts bind
	// its hash and observation commitment without copying role subjects/usernames.
	facts, err := json.Marshal(struct {
		Command            string       `json:"command_id"`
		Admission          string       `json:"admission_uid"`
		SignedResultDigest ports.Digest `json:"signed_result_digest"`
		ObservationDigest  ports.Digest `json:"observation_digest"`
		ReadBackVerified   bool         `json:"read_back_verified"`
		Success            bool         `json:"success"`
		ObservedRevision   int64        `json:"observed_revision"`
		ObservedAt         time.Time    `json:"observed_at"`
	}{command.CommandID, r.Kubernetes.AdmissionUID, signedDigest, r.ObservationDigest, r.ReadBackVerified, r.Success, r.ObservedRevision, r.ObservedAt})
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, eventstore.ErrIntegrity
	}
	events[0].Change.Facts = facts
	return events, nil
}

func sameNativeObject(want, got *kube.Object) bool {
	a, err := canon.New().Digest(want)
	if err != nil {
		return false
	}
	b, err := canon.New().Digest(got)
	return err == nil && a == b
}
