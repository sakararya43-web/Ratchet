//go:build integration

package workflow_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

type system struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	store     *eventstore.Store
	engine    *policy.Engine
	tenant    string
	key       []byte
	authority *trust.Store
	root      ports.Digest
}

func setup(t *testing.T) system {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	if os.Getenv("RATCHET_MIGRATION_DSN") == "" {
		t.Fatal("real PostgreSQL required")
	}
	if err := eventstore.Migrate(ctx, os.Getenv("RATCHET_MIGRATION_DSN")); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	tenant := "flow_" + uuid.NewString()
	key := bytes.Repeat([]byte{61}, 32)
	data := graph.Data{Nodes: []graph.Node{{ID: "user:requester", Type: "Human", DisplayName: "Private Person"}, {ID: "user:owner", Type: "Human"}, {ID: "user:sec1", Type: "Human"}, {ID: "user:sec2", Type: "Human"}, {ID: "role:finance", Type: "Role"}, {ID: "role:admin", Type: "Role"}, {ID: "role:security-lead", Type: "Role"}, {ID: "reports", Type: "Resource", Tier: 2}, {ID: "wallet", Type: "Resource", Tier: 0}}, Edges: []graph.Edge{{Source: "role:finance", Target: "reports", Kind: "GRANTS", Action: "read"}, {Source: "role:admin", Target: "wallet", Kind: "GRANTS", Action: "sign"}, {Source: "user:sec1", Target: "role:security-lead", Kind: "ASSIGNED"}, {Source: "user:sec2", Target: "role:security-lead", Kind: "ASSIGNED"}}}
	if _, err := store.IngestGraph(ctx, eventstore.GraphInput{TenantID: tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{1}).String(), ToRevision: 10, Complete: true, Snapshot: &data}, key); err != nil {
		t.Fatal(err)
	}
	authority, err := trust.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	leader, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&leader.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := authority.InitGenesis(tenant, 1, 1, []trust.AuthorityMember{{ActorID: "authority-leader", PublicKey: public, IsActive: true}})
	if err != nil {
		t.Fatal(err)
	}
	modules := map[string]string{}
	for _, name := range []string{"change.rego", "authz.rego"} {
		raw, err := os.ReadFile("../../policies/" + name)
		if err != nil {
			t.Fatal(err)
		}
		modules[name] = string(raw)
	}
	bundle, err := authority.ProposeBundle(tenant, "1.0.0", "test-only ephemeral Authority", modules, map[string]any{"resource_owners": map[string]any{"reports": []string{"user:owner"}}})
	if err != nil {
		t.Fatal(err)
	}
	signing := trust.ComputePolicySigningDigest(tenant, 1, bundle.BundleDigest)
	sig, err := ecdsa.SignASN1(rand.Reader, leader, signing[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: sig}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.NewEngine()
	manager := policy.Manager{Store: store, Engine: engine, Authority: authority, Root: genesis.GenesisDigest, Tenant: tenant}
	if err := manager.Activate(ctx, raw); err != nil {
		t.Fatal(err)
	}
	restored := policy.NewEngine()
	manager.Engine = restored
	if err := manager.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := restored.Current(tenant)
	raw[len(raw)/2] ^= 1
	if manager.Activate(ctx, raw) == nil {
		t.Fatal("invalid bundle replaced active policy")
	}
	after, _ := restored.Current(tenant)
	if before.Hash != after.Hash {
		t.Fatal("last valid bundle lost")
	}
	return system{ctx, pool, store, engine, tenant, key, authority, genesis.GenesisDigest}
}
func start(t *testing.T, s *workflow.Service, ctx context.Context) {
	t.Helper()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Stop(stop); err != nil {
			t.Error(err)
		}
	})
}
func waitState(t *testing.T, sys system, id string, state domain.State) domain.Change {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := sys.store.ReadChange(sys.ctx, sys.tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if c.State == state {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("wanted %s got %s (%v)", state, c.State, c.Decision.Reasons)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func TestRealRiverAssessmentIdempotencyContextAndProjectionRecovery(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	input := workflow.Submit{Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: actor.ID, Access: "role:finance"}, Justification: "Private business justification remains encrypted", CommandID: uuid.New()}
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := service.Submit(sys.ctx, actor, input)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- c.ID
		}()
	}
	wg.Wait()
	close(ids)
	var id string
	for value := range ids {
		if id != "" && id != value {
			t.Fatal("duplicate request created")
		}
		id = value
	}
	if id == "" {
		t.Fatal("no committed request")
	}
	changed := input
	changed.CorrelationID = uuid.NewString()
	if _, err := service.Submit(sys.ctx, actor, changed); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("idempotency key accepted a different correlation", err)
	}
	changed = input
	changed.MinGraphVersion = 1
	if _, err := service.Submit(sys.ctx, actor, changed); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("idempotency key accepted different consistency requirements", err)
	}
	start(t, service, sys.ctx)
	c := waitState(t, sys, id, domain.AwaitingApproval)
	if c.Decision.Quorum != 1 || c.Envelope == nil || c.Digest.IsZero() || len(c.Facts) == 0 {
		t.Fatal("missing replayable assessment", c)
	}
	if _, err := service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, id, uuid.New(), c.Revision, c.Digest, ports.ApprovalSubmission{}); !errors.Is(err, workflow.ErrDependency) {
		t.Fatal("missing real verifier did not block", err)
	}
	if current, _ := sys.store.ReadChange(sys.ctx, sys.tenant, id); current.State != domain.AwaitingApproval {
		t.Fatal("unverified approval advanced state")
	}
	events, err := sys.store.LoadStream(sys.ctx, sys.tenant, "change:"+id)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if bytes.Contains(event.Entry.Canonical, []byte(input.Justification)) || bytes.Contains(event.Entry.Canonical, []byte("Private Person")) {
			t.Fatal("personal context leaked into ledger")
		}
	}
	held, err := service.Review(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, id, uuid.New(), c.Revision, "MORE_INFO", "Please explain the reporting requirement")
	if err != nil {
		t.Fatal(err)
	}
	if held.State != domain.Held || held.Envelope != nil {
		t.Fatal("hold retained approval context")
	}
	updated, err := service.ProvideContext(sys.ctx, actor, id, uuid.New(), held.Revision, "The daily finance report requires this exact reader role")
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != domain.Submitted {
		t.Fatal(updated.State)
	}
	reassessed := waitState(t, sys, id, domain.AwaitingApproval)
	if reassessed.Digest == c.Digest {
		t.Fatal("new context reused old envelope")
	}
	if err := service.Rebuild(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
	list, _, _, err := service.List(sys.ctx, actor, 0, 200, "", 0)
	if err != nil || len(list) != 1 || list[0].Revision != reassessed.Revision {
		t.Fatal("rebuild lost authoritative state", err)
	}
	if _, _, err := sys.store.VerifyTenant(sys.ctx, sys.tenant); err != nil {
		t.Fatal(err)
	}
	admin, err := service.Submit(sys.ctx, actor, workflow.Submit{Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: actor.ID, Access: "role:admin"}, Justification: "Security-reviewed wallet administration request", CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	sensitive := waitState(t, sys, admin.ID, domain.AwaitingApproval)
	if sensitive.Decision.Quorum != 2 || !slices.Equal(sensitive.Decision.Groups, []string{"role:security-lead"}) {
		t.Fatal("tier-0 request did not require two security leads")
	}
}
func signCapability(t *testing.T, tenant string) (*workflow.Execution, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, core, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capability := workflow.Capability{Tenant: tenant, Connector: "source", Protocol: "RATCHET_EXEC_V1", Expires: time.Now().Add(time.Hour), BoundCommands: true, AtomicPreconditions: true, DurableDedup: true, IndependentReadBack: true}
	digest, err := canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_CAPABILITY_V1", capability})
	if err != nil {
		t.Fatal(err)
	}
	capability.Signature = ed25519.Sign(private, digest[:])
	execution, err := workflow.NewExecution(tenant, "source", public, core, capability)
	if err != nil {
		t.Fatal(err)
	}
	return execution, private
}
func assertion(t *testing.T, tenant, actor string, digest ports.Digest, key *ecdsa.PrivateKey, credential []byte) ports.ApprovalSubmission {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	challenge := approval.ComputeApprovalChallenge(tenant, actor, digest, nonce)
	clientData, err := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": "https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("console.test"))
	auth := make([]byte, 37)
	copy(auth, rp[:])
	auth[32] = 5
	clientHash := sha256.Sum256(clientData)
	signed := append(slices.Clone(auth), clientHash[:]...)
	hash := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return ports.ApprovalSubmission{TenantID: tenant, ActorID: actor, CredentialID: credential, ClientDataJSON: clientData, AuthenticatorData: auth, Signature: sig, ChallengeNonce: nonce}
}
func signedResult(t *testing.T, result workflow.ExecutionResult, key ed25519.PrivateKey) []byte {
	t.Helper()
	result.Signature = nil
	digest, err := canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_RESULT_V1", result})
	if err != nil {
		t.Fatal(err)
	}
	result.Signature = ed25519.Sign(key, digest[:])
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// This is a real-cryptography protocol fixture, not a browser passkey ceremony
// or the unsafe peer handler. Production mounting remains separately gated.
func readyExecution(t *testing.T) (system, *workflow.Service, domain.Change, ed25519.PrivateKey, func() *workflow.Service) {
	t.Helper()
	sys := setup(t)
	credentials := approval.NewCredentialStore()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte(uuid.NewString())
	if err := credentials.SaveCredential(sys.tenant, "user:owner", "test cryptographic fixture", &webauthn.Credential{ID: credential, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	verifier, err := approval.NewApprovalVerifier(credentials, "console.test", []string{"https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	execution, connectorKey := signCapability(t, sys.tenant)
	open := func() *workflow.Service {
		service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant}, execution)
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	service := open()
	start(t, service, sys.ctx)
	created, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "Finance reporting access for the daily report", CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	c := waitState(t, sys, created.ID, domain.AwaitingApproval)
	proof := assertion(t, sys.tenant, "user:owner", c.Digest, key, credential)
	if _, err := service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), c.Revision, c.Digest, proof); err != nil {
		t.Fatal(err)
	}
	c = waitState(t, sys, c.ID, domain.Executing)
	return sys, service, c, connectorKey, open
}
func TestBoundDispatchReadbackRefusalAndUncertainWriteReconciliation(t *testing.T) {
	sys, service, c, connectorKey, _ := readyExecution(t)
	result := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "source", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true}
	wrongCorrelation := result
	wrongCorrelation.CorrelationID = uuid.NewString()
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, wrongCorrelation, connectorKey)); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("wrong correlation accepted", err)
	}
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, result, connectorKey)); err != nil {
		t.Fatal(err)
	}
	if current, _ := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID); current.State != domain.Executing {
		t.Fatal("write ACK marked executed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var queries int64
		err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
			return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.outbox WHERE tenant_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'verify_only'='true'`, sys.tenant).Scan(&queries)
		})
		if err != nil {
			t.Fatal(err)
		}
		if queries > 0 {
			current, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			var pending int64
			if err := sys.pool.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet_jobs.river_job WHERE kind='ratchet_change_v1' AND args->>'tenant_id'=$1 AND args->>'request_id'=$2 AND (args->>'revision')::bigint=$3 AND args->>'operation'='reconcile' AND state='scheduled' AND scheduled_at>clock_timestamp()`, sys.tenant, c.ID, current.Revision).Scan(&pending); err != nil {
				t.Fatal(err)
			}
			if pending == 0 {
				t.Fatal("lost read-back reply would end durable reconciliation")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("uncertain write did not enqueue a read-only reconciliation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	result.MessageID = uuid.NewString()
	result.ReadBackVerified = true
	result.AppliedAt = c.UpdatedAt.Add(time.Microsecond)
	result.ObservedTenant = sys.tenant
	result.ObservedTarget = "user:requester"
	result.ObservedRoles = []string{"role:admin"}
	result.ObservedRevision = 11
	result.ObservedAt = time.Now().UTC()
	result.ObservationDigest, _ = canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{result.ObservedTenant, result.ObservedTarget, result.ObservedRoles, result.ObservedRevision, result.ObservedAt})
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, result, connectorKey)); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("mismatched readback accepted", err)
	}
	result.MessageID = uuid.NewString()
	result.ObservedRoles = []string{"role:finance"}
	result.ObservationDigest, _ = canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{result.ObservedTenant, result.ObservedTarget, result.ObservedRoles, result.ObservedRevision, result.ObservedAt})
	raw := signedResult(t, result, connectorKey)
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, raw); err != nil {
		t.Fatal(err)
	}
	waitState(t, sys, c.ID, domain.Executed)
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, raw); err != nil {
		t.Fatal("duplicate readback", err)
	}
	result.ObservedRoles = []string{"role:admin"}
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, result, connectorKey)); !errors.Is(err, eventstore.ErrIdempotencyConflict) {
		t.Fatal("message ID reused with new evidence", err)
	}
}

func TestVerifiedRefusalRecordsFailedWithoutInventingApplication(t *testing.T) {
	sys, service, c, key, _ := readyExecution(t)
	result := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "source", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: false, ReadBackVerified: true, ObservedTenant: sys.tenant, ObservedTarget: c.Intent.Target, ObservedRoles: []string{}, ObservedRevision: 10, ObservedAt: time.Now().UTC()}
	result.ObservationDigest, _ = canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{result.ObservedTenant, result.ObservedTarget, result.ObservedRoles, result.ObservedRevision, result.ObservedAt})
	if err := service.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, result, key)); err != nil {
		t.Fatal(err)
	}
	failed := waitState(t, sys, c.ID, domain.Failed)
	if len(failed.Facts) == 0 {
		t.Fatal("verified refusal evidence lost")
	}
}

func TestReplacementWorkerRecoversUncertainExecutionWithoutWritingAgain(t *testing.T) {
	sys, original, c, key, reopen := readyExecution(t)
	stop, cancel := context.WithTimeout(sys.ctx, 5*time.Second)
	defer cancel()
	if err := original.Stop(stop); err != nil {
		t.Fatal(err)
	}
	replacement := reopen()
	start(t, replacement, sys.ctx)
	ack := workflow.ExecutionResult{SchemaVersion: 1, Tenant: sys.tenant, Connector: "source", MessageID: uuid.NewString(), CommandID: c.ExecutionID, RequestID: c.ID, CorrelationID: c.CorrelationID, EnvelopeDigest: c.Digest, Success: true}
	if err := replacement.RecordExecutionResult(sys.ctx, sys.tenant, signedResult(t, ack, key)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var writes, probes int64
		err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
			return tx.QueryRow(sys.ctx, `SELECT count(*) FILTER (WHERE NOT (convert_from(payload,'UTF8')::jsonb->>'verify_only')::boolean),count(*) FILTER (WHERE (convert_from(payload,'UTF8')::jsonb->>'verify_only')::boolean) FROM ratchet.outbox WHERE tenant_id=$1 AND subject=$2`, sys.tenant, "ratchet."+sys.tenant+".exec.source").Scan(&writes, &probes)
		})
		if err != nil {
			t.Fatal(err)
		}
		if writes != 1 {
			t.Fatalf("recovery produced %d write commands", writes)
		}
		if probes > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh worker did not recover the durable execution attempt")
		}
		time.Sleep(20 * time.Millisecond)
	}
	current, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || current.State != domain.Executing || current.ExecutionID != c.ExecutionID {
		t.Fatal("recovery invented completion or changed command identity", err)
	}
}

func TestIndependentWorkerInstancesConsumeOnlyTheirTenantQueues(t *testing.T) {
	a, b := setup(t), setup(t)
	first, err := workflow.New(a.pool, a.store, a.engine, a.key, nil, []string{a.tenant})
	if err != nil {
		t.Fatal(err)
	}
	second, err := workflow.New(b.pool, b.store, b.engine, b.key, nil, []string{b.tenant})
	if err != nil {
		t.Fatal(err)
	}
	start(t, first, a.ctx)
	start(t, second, b.ctx)
	type expected struct {
		sys system
		id  string
	}
	requests := []expected{}
	for range 8 {
		for _, item := range []struct {
			sys     system
			service *workflow.Service
		}{{a, first}, {b, second}} {
			c, err := item.service.Submit(item.sys.ctx, workflow.Actor{TenantID: item.sys.tenant, ID: "user:requester"}, workflow.Submit{Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "Independent tenant reporting business request", CommandID: uuid.New()})
			if err != nil {
				t.Fatal(err)
			}
			requests = append(requests, expected{item.sys, c.ID})
		}
	}
	for _, request := range requests {
		c := waitState(t, request.sys, request.id, domain.AwaitingApproval)
		if c.Decision.Quorum != 1 {
			t.Fatal("foreign worker evaluated tenant policy")
		}
	}
	if err := first.Authorize(a.ctx, workflow.Actor{TenantID: b.tenant, ID: "user:requester"}, "view"); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("foreign service tenant accepted", err)
	}
}
