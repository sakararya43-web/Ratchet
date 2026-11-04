//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

type cookieTransport struct {
	base         http.RoundTripper
	cookie       *http.Cookie
	csrf, origin string
}

func (t cookieTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	copy.AddCookie(t.cookie)
	copy.Header.Set("Origin", t.origin)
	copy.Header.Set("X-CSRF-Token", t.csrf)
	return t.base.RoundTrip(copy)
}
func TestConsoleRuntimeRealSessionsPolicyRiverAndConnectReview(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	if os.Getenv("RATCHET_MIGRATION_DSN") == "" {
		t.Fatal("real PostgreSQL/NATS required")
	}
	if err := eventstore.Migrate(ctx, os.Getenv("RATCHET_MIGRATION_DSN")); err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.New(ctx, os.Getenv("RATCHET_MIGRATION_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	tenant := "console_" + uuid.NewString()
	password := "private-test-password-" + uuid.NewString()
	for _, id := range []string{"user:requester", "user:owner", "user:investigator"} {
		if err := api.ProvisionUser(ctx, admin, api.Principal{TenantID: tenant, ActorID: id}, password); err != nil {
			t.Fatal(err)
		}
	}
	key := bytes.Repeat([]byte{23}, 32)
	data := graph.Data{Nodes: []graph.Node{{ID: "user:requester", Type: "Human"}, {ID: "user:owner", Type: "Human"}, {ID: "role:finance", Type: "Role"}, {ID: "reports", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{Source: "role:finance", Target: "reports", Kind: "GRANTS", Action: "read"}}}
	data.Nodes = append(data.Nodes, graph.Node{ID: "user:investigator", Type: "Human"}, graph.Node{ID: "role:security-lead", Type: "Role"})
	data.Edges = append(data.Edges, graph.Edge{Source: "user:investigator", Target: "role:security-lead", Kind: "ASSIGNED"})
	if _, err := store.IngestGraph(ctx, eventstore.GraphInput{TenantID: tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{8}).String(), ToRevision: 10, Snapshot: &data, Complete: true}, key); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, keyPath, _, client := runtimePKI(t, dir)
	// Race instrumentation makes the actual Argon2id work slower; keep its
	// client deadline inside the runtime's existing 10-second write bound.
	client.Timeout = 8 * time.Second
	authorityFile := filepath.Join(dir, "authority.json")
	authority, err := trust.NewStore(authorityFile)
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
	genesis, err := authority.InitGenesis(tenant, 1, 1, []trust.AuthorityMember{{ActorID: "authority", PublicKey: public, IsActive: true}})
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
	bundle, err := authority.ProposeBundle(tenant, "1.0.0", "runtime test signed policy", modules, map[string]any{"resource_owners": map[string]any{"reports": []string{"user:owner"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := trust.ComputePolicySigningDigest(tenant, 1, bundle.BundleDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, leader, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "authority", Signature: signature}); err != nil {
		t.Fatal(err)
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, bundleRaw, 0600); err != nil {
		t.Fatal(err)
	}
	origin := "https://console.test"
	natsURL := os.Getenv("RATCHET_NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:54222"
	}
	config := map[string]any{"origin": origin, "session_key_hex": hex.EncodeToString(bytes.Repeat([]byte{41}, 32)), "graph_key_hex": hex.EncodeToString(key), "cursor_key_hex": hex.EncodeToString(bytes.Repeat([]byte{42}, 32)), "server_cert": cert, "server_key": keyPath, "nats_url": natsURL, "tenants": []map[string]string{{"tenant_id": tenant, "authority_file": authorityFile, "genesis_digest": genesis.GenesisDigest.String(), "bundle_file": bundlePath}}}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "console.json")
	if err := os.WriteFile(configPath, configRaw, 0600); err != nil {
		t.Fatal(err)
	}
	runtimeCtx, stop := context.WithCancel(ctx)
	address := listenerAddress{make(chan string, 1)}
	finished := make(chan error, 1)
	go func() {
		finished <- runConsole(runtimeCtx, []string{"--config", configPath, "--listen", "127.0.0.1:0"}, address)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("console did not stop")
		}
	})
	var host string
	select {
	case host = <-address.ready:
	case err := <-finished:
		t.Fatalf("console startup %v", err)
	case <-ctx.Done():
		t.Fatal("console did not listen")
	}
	base := "https://" + host
	login := func(actor string) *http.Client {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"tenant_id": tenant, "actor_id": actor, "password": password})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/auth/login", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			raw, _ := io.ReadAll(response.Body)
			t.Fatalf("login %d %s", response.StatusCode, raw)
		}
		var logged struct {
			CSRF string `json:"csrf_token"`
		}
		if err := json.NewDecoder(response.Body).Decode(&logged); err != nil {
			t.Fatal(err)
		}
		cookies := response.Cookies()
		if len(cookies) != 1 {
			t.Fatal("no login cookie")
		}
		return &http.Client{Transport: cookieTransport{client.Transport, cookies[0], logged.CSRF, origin}, Timeout: 3 * time.Second}
	}
	requester := login("user:requester")
	owner := login("user:owner")
	changes := ratchetv1connect.NewChangeServiceClient(requester, base+"/api")
	reviews := ratchetv1connect.NewChangeServiceClient(owner, base+"/api")
	mutation := func(revision int64) *v1.MutationContext {
		return &v1.MutationContext{IdempotencyKey: uuid.NewString(), CorrelationId: uuid.NewString(), ExpectedRevision: revision}
	}
	input := &v1.SubmitChangeRequest{TenantId: tenant, Kind: "ROLE_ASSIGN", TargetIdentity: "user:requester", RequestedAccess: "role:finance", Justification: "Daily finance report needs this reader role", Mutation: mutation(0)}
	created, err := changes.SubmitChange(ctx, connect.NewRequest(input))
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := changes.SubmitChange(ctx, connect.NewRequest(input))
	if err != nil || duplicate.Msg.Request.RequestId != created.Msg.Request.RequestId {
		t.Fatal("request duplicate", err)
	}
	id := created.Msg.Request.RequestId
	wait := func() *v1.ChangeRequest {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			result, err := changes.GetChange(ctx, connect.NewRequest(&v1.GetChangeRequest{TenantId: tenant, RequestId: id}))
			if err != nil {
				t.Fatal(err)
			}
			if result.Msg.Request.Status == "AWAITING_APPROVAL" {
				return result.Msg.Request
			}
			if time.Now().After(deadline) {
				t.Fatal("assessment did not complete")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	assessed := wait()
	investigations := ratchetv1connect.NewChangeServiceClient(login("user:investigator"), base+"/api")
	evidence, err := investigations.GetDecisionEvidence(ctx, connect.NewRequest(&v1.GetDecisionEvidenceRequest{TenantId: tenant, RequestId: id}))
	if err != nil {
		t.Fatal("real authenticated evidence export", err)
	}
	var exported workflow.DecisionEvidence
	if err := json.Unmarshal(evidence.Msg.CanonicalEvidenceJson, &exported); err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.ReplayDecision(ctx, exported, genesis.GenesisDigest, exported.EventHash); err != nil {
		t.Fatal("exported replay", err)
	}
	if _, err := changes.GetDecisionEvidence(ctx, connect.NewRequest(&v1.GetDecisionEvidenceRequest{TenantId: tenant, RequestId: id})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("requester obtained investigator evidence", err)
	}
	history, err := investigations.ListPolicyHistory(ctx, connect.NewRequest(&v1.ListPolicyHistoryRequest{TenantId: tenant, PageSize: 1}))
	if err != nil || len(history.Msg.Activations) != 1 || history.Msg.Activations[0].RegistryEpoch != 1 {
		t.Fatal("governance history", err)
	}
	if _, err := changes.ListPolicyHistory(ctx, connect.NewRequest(&v1.ListPolicyHistoryRequest{TenantId: tenant})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary session obtained governance history", err)
	}
	for _, kind := range []string{"CHANGE_APPROVER", "MODIFY_QUORUM", "ROTATE_REGISTRY", "MODIFY_TRUST_ROOT"} {
		if _, err := investigations.SubmitChange(ctx, connect.NewRequest(&v1.SubmitChangeRequest{TenantId: tenant, Kind: kind, TargetIdentity: "role:security-lead", RequestedAccess: "override", Justification: "An administrative session must not bypass governance", Mutation: mutation(0)})); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatal("target request bypassed Authority governance", kind, err)
		}
	}
	canonicalDigest, err := canon.New().Digest(json.RawMessage(assessed.CanonicalApprovalEnvelopeJson))
	if err != nil || canonicalDigest.String() != assessed.ChangeDigest || assessed.RequiredQuorum != 1 {
		t.Fatal("approval bytes not bound", err)
	}
	_, err = reviews.ApproveChange(ctx, connect.NewRequest(&v1.ApproveChangeRequest{TenantId: tenant, RequestId: id, ApproverId: "user:owner", AssertionResponseJson: "{}", Mutation: mutation(assessed.Revision), ApprovedEnvelopeDigest: assessed.ChangeDigest}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatal("unsafe passkey dependency admitted", err)
	}
	_, err = changes.GetChange(ctx, connect.NewRequest(&v1.GetChangeRequest{TenantId: "other", RequestId: id}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("cross-tenant read", err)
	}
	held, err := reviews.RequestMoreInfo(ctx, connect.NewRequest(&v1.RequestMoreInfoRequest{TenantId: tenant, RequestId: id, ActorId: "user:owner", Question: "Clarify the reporting purpose", Mutation: mutation(assessed.Revision)}))
	if err != nil {
		t.Fatal(err)
	}
	if held.Msg.Request.Status != "HELD" {
		t.Fatal(held.Msg.Request.Status)
	}
	_, err = changes.ProvideContext(ctx, connect.NewRequest(&v1.ProvideContextRequest{TenantId: tenant, RequestId: id, Context: "The daily reconciliation report is required by finance", Mutation: mutation(held.Msg.Request.Revision)}))
	if err != nil {
		t.Fatal(err)
	}
	reassessed := wait()
	if reassessed.ChangeDigest == assessed.ChangeDigest {
		t.Fatal("stale approval digest reused")
	}
	overview := ratchetv1connect.NewOverviewServiceClient(owner, base+"/api")
	attention, err := overview.GetAttentionItems(ctx, connect.NewRequest(&v1.GetAttentionItemsRequest{TenantId: tenant}))
	if err != nil || len(attention.Msg.PendingRequests) != 1 {
		t.Fatal("real attention projection", err)
	}
	graphClient := ratchetv1connect.NewGraphServiceClient(requester, base+"/api")
	reach, err := graphClient.GetReach(ctx, connect.NewRequest(&v1.GetReachRequest{TenantId: tenant, IdentityId: "user:requester"}))
	if err != nil || reach.Msg.ReachByTier["2"] != 0 {
		t.Fatal("pending request changed graph", err)
	}
	response, err := client.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("missing workflow dependency reported ready")
	}
	unsafeRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/passkeys/assert/simulate", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	response, err = owner.Do(unsafeRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatal("simulated assertion route exposed")
	}
}
