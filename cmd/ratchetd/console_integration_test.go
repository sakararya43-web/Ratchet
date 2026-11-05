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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
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
	data.Nodes = append(data.Nodes, graph.Node{ID: "user:compromised", Type: "Human"}, graph.Node{ID: "role:admin", Type: "Role"}, graph.Node{ID: "wallet", Type: "Resource", Tier: 0})
	data.Edges = append(data.Edges, graph.Edge{Source: "user:compromised", Target: "role:admin", Kind: "ASSIGNED"}, graph.Edge{Source: "user:compromised", Target: "role:finance", Kind: "ASSIGNED"}, graph.Edge{Source: "role:admin", Target: "wallet", Kind: "GRANTS", Action: "sign"})
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
	config["containment_costs"] = map[string]int64{"ROLE_REVOKE": 1, "RESTRICT_ACCOUNT": 100}
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
	requesterView := wait()
	if requesterView.ChangeDigest != "" || len(requesterView.CanonicalApprovalEnvelopeJson) != 0 || requesterView.PolicyBundleHash != "" || len(requesterView.RequiredApproverGroups) != 0 || requesterView.Justification != input.Justification {
		t.Fatal("requester response exposed investigator evidence")
	}
	approvalView, err := reviews.GetChange(ctx, connect.NewRequest(&v1.GetChangeRequest{TenantId: tenant, RequestId: id}))
	if err != nil {
		t.Fatal(err)
	}
	assessed := approvalView.Msg.Request
	investigatorClient := login("user:investigator")
	investigations := ratchetv1connect.NewChangeServiceClient(investigatorClient, base+"/api")
	containment := ratchetv1connect.NewContainmentServiceClient(investigatorClient, base+"/api")
	planInput := &v1.PlanContainmentRequest{TenantId: tenant, CompromisedIdentity: "user:compromised", Mutation: mutation(0)}
	planned, err := containment.PlanContainment(ctx, connect.NewRequest(planInput))
	if err != nil {
		t.Fatal("real containment plan API", err)
	}
	if !planned.Msg.Plan.MinimumProved || !planned.Msg.Plan.ProposedZeroTier0Proved || planned.Msg.Plan.DisruptionCost != 1 || len(planned.Msg.Plan.RecommendedRevocations) != 1 || planned.Msg.Plan.RecommendedRevocations[0].ResourceOrRole != "role:admin" {
		t.Fatal("incorrect proposed cut", planned.Msg.Plan)
	}
	planDigest, err := canon.New().Digest(json.RawMessage(planned.Msg.Plan.CanonicalPlanJson))
	if err != nil || planDigest.String() != planned.Msg.Plan.PlanDigest {
		t.Fatal("canonical plan not bound", err)
	}
	again, err := containment.PlanContainment(ctx, connect.NewRequest(planInput))
	if err != nil || again.Msg.Plan.PlanId != planned.Msg.Plan.PlanId {
		t.Fatal("plan retry duplicated proposal", err)
	}
	ordinaryContainment := ratchetv1connect.NewContainmentServiceClient(requester, base+"/api")
	if _, err := ordinaryContainment.PlanContainment(ctx, connect.NewRequest(&v1.PlanContainmentRequest{TenantId: tenant, CompromisedIdentity: "user:compromised", Mutation: mutation(0)})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary user obtained containment plan", err)
	}
	if _, err := containment.ExecuteContainment(ctx, connect.NewRequest(&v1.ExecuteContainmentRequest{TenantId: tenant, PlanId: planned.Msg.Plan.PlanId, ResponderId: "user:investigator", Mutation: mutation(0)})); err == nil {
		t.Fatal("planning API executed an unconfirmed containment")
	}
	audits := ratchetv1connect.NewAuditServiceClient(investigatorClient, base+"/api")
	incidents := ratchetv1connect.NewIncidentServiceClient(investigatorClient, base+"/api")
	openInput := &v1.OpenIncidentRequest{TenantId: tenant, PlanId: planned.Msg.Plan.PlanId, PlanDigest: planned.Msg.Plan.PlanDigest, Mutation: mutation(0)}
	opened, err := incidents.OpenIncident(ctx, connect.NewRequest(openInput))
	if err != nil || opened.Msg.Incident.Status != "OPEN" || len(opened.Msg.Incident.ActionsTaken) != 0 || len(opened.Msg.Incident.ResidualRoutes) == 0 || len(opened.Msg.Incident.RestorationPrerequisites) == 0 {
		t.Fatal("real incident investigation", err)
	}
	duplicateIncident, err := incidents.OpenIncident(ctx, connect.NewRequest(openInput))
	if err != nil || duplicateIncident.Msg.Incident.IncidentId != opened.Msg.Incident.IncidentId {
		t.Fatal("HTTP incident retry duplicated opening", err)
	}
	openInput.Mutation = mutation(0)
	if _, err := incidents.OpenIncident(ctx, connect.NewRequest(openInput)); err != nil {
		t.Fatal(err)
	}
	incidentFirst, err := incidents.ListIncidents(ctx, connect.NewRequest(&v1.ListIncidentsRequest{TenantId: tenant, StatusFilter: "OPEN", PageSize: 1}))
	if err != nil || len(incidentFirst.Msg.Incidents) != 1 || incidentFirst.Msg.NextPageToken == "" {
		t.Fatal("incident pagination", err)
	}
	openInput.Mutation = mutation(0)
	if _, err := incidents.OpenIncident(ctx, connect.NewRequest(openInput)); err != nil {
		t.Fatal(err)
	}
	incidentTail, err := incidents.ListIncidents(ctx, connect.NewRequest(&v1.ListIncidentsRequest{TenantId: tenant, StatusFilter: "OPEN", PageSize: 1, PageToken: incidentFirst.Msg.NextPageToken}))
	if err != nil || len(incidentTail.Msg.Incidents) != 1 || incidentTail.Msg.SnapshotEndSequence != incidentFirst.Msg.SnapshotEndSequence || incidentTail.Msg.NextPageToken != "" {
		t.Fatal("incident pagination admitted later opening", err)
	}
	if _, err := incidents.ListIncidents(ctx, connect.NewRequest(&v1.ListIncidentsRequest{TenantId: tenant, StatusFilter: "CONTAINED", PageToken: incidentFirst.Msg.NextPageToken})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("incident cursor changed filter", err)
	}
	incidentRead, err := incidents.GetIncident(ctx, connect.NewRequest(&v1.GetIncidentRequest{TenantId: tenant, IncidentId: opened.Msg.Incident.IncidentId}))
	if err != nil || incidentRead.Msg.Incident.ContainmentPlan.PlanDigest != planned.Msg.Plan.PlanDigest || incidentRead.Msg.Incident.ObservedGraphVersion == 0 {
		t.Fatal("incident source replay", err)
	}
	ordinaryIncidents := ratchetv1connect.NewIncidentServiceClient(requester, base+"/api")
	if _, err := ordinaryIncidents.GetIncident(ctx, connect.NewRequest(&v1.GetIncidentRequest{TenantId: tenant, IncidentId: opened.Msg.Incident.IncidentId})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary user obtained investigator incident", err)
	}
	if _, err := ordinaryIncidents.OpenIncident(ctx, connect.NewRequest(openInput)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary user opened incident", err)
	}
	if _, err := incidents.GetIncident(ctx, connect.NewRequest(&v1.GetIncidentRequest{TenantId: "other", IncidentId: opened.Msg.Incident.IncidentId})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("cross tenant incident access", err)
	}
	investigatorOverview := ratchetv1connect.NewOverviewServiceClient(investigatorClient, base+"/api")
	incidentAttention, err := investigatorOverview.GetAttentionItems(ctx, connect.NewRequest(&v1.GetAttentionItemsRequest{TenantId: tenant}))
	if err != nil || len(incidentAttention.Msg.ActiveIncidents) != 3 {
		t.Fatal("active investigations missing from authorized overview", err)
	}
	page, err := audits.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant, PageSize: 2}))
	if err != nil {
		t.Fatal("real audit export", err)
	}
	end, tip := page.Msg.SnapshotEndSequence, page.Msg.SnapshotEndHash
	firstToken := page.Msg.NextPageToken
	if firstToken == "" {
		t.Fatal("audit pagination not exercised")
	}
	if _, err := containment.PlanContainment(ctx, connect.NewRequest(&v1.PlanContainmentRequest{TenantId: tenant, CompromisedIdentity: "user:compromised", Mutation: mutation(0)})); err != nil {
		t.Fatal(err)
	}
	var previous ports.Digest
	var sequence int64
	for {
		if page.Msg.SnapshotEndSequence != end || page.Msg.SnapshotEndHash != tip || page.Msg.PagePreviousHash != previous.String() {
			t.Fatal("audit cursor changed snapshot or chain anchor")
		}
		for _, event := range page.Msg.Chain {
			before, err := ports.DigestFromHex(event.PreviousEventHash)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := ports.DigestFromHex(event.EventHash)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Verify(canon.New(), ledger.Entry{Canonical: event.CanonicalContent, Previous: before, Hash: hash}, tenant, sequence+1, previous); err != nil {
				t.Fatal("exported chain failed independent verification", err)
			}
			if bytes.Contains(event.CanonicalContent, []byte(input.Justification)) {
				t.Fatal("private justification leaked in raw chain")
			}
			previous = hash
			sequence = event.SequenceNumber
		}
		if page.Msg.NextPageToken == "" {
			break
		}
		page, err = audits.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant, PageSize: 2, PageToken: page.Msg.NextPageToken}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if sequence != end || previous.String() != tip {
		t.Fatal("snapshot export omitted or included later evidence")
	}
	if _, err := audits.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant, PageToken: "!" + firstToken[1:]})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("tampered audit cursor accepted", err)
	}
	ordinaryAudit := ratchetv1connect.NewAuditServiceClient(requester, base+"/api")
	if _, err := ordinaryAudit.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant, PageToken: firstToken})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary session exported chain", err)
	}
	search, err := audits.QueryAuditEvents(ctx, connect.NewRequest(&v1.QueryAuditEventsRequest{TenantId: tenant, RequestId: id, ResourceId: "reports", PageSize: 1}))
	if err != nil || len(search.Msg.Events) != 1 || search.Msg.NextPageToken == "" {
		t.Fatal("indexed audit search", err)
	}
	if len(search.Msg.Events[0].CanonicalContent) != 0 || strings.Contains(search.Msg.Events[0].EventPayloadJson, input.Justification) || strings.Contains(search.Msg.Events[0].EventPayloadJson, "assertion") {
		t.Fatal("display search exposed raw evidence")
	}
	if _, err := audits.QueryAuditEvents(ctx, connect.NewRequest(&v1.QueryAuditEventsRequest{TenantId: tenant, RequestId: uuid.NewString(), ResourceId: "reports", PageToken: search.Msg.NextPageToken})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("search cursor changed filters", err)
	}
	if _, err := ordinaryAudit.QueryAuditEvents(ctx, connect.NewRequest(&v1.QueryAuditEventsRequest{TenantId: tenant})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary session searched investigator audit", err)
	}
	var lastCheckpoint string
	for range 2 {
		prepareInput := &v1.PrepareCheckpointRequest{TenantId: tenant, Mutation: mutation(0)}
		prepared, err := audits.PrepareCheckpoint(ctx, connect.NewRequest(prepareInput))
		if err != nil {
			t.Fatal("authenticated checkpoint preparation", err)
		}
		duplicate, err := audits.PrepareCheckpoint(ctx, connect.NewRequest(prepareInput))
		if err != nil || !bytes.Equal(prepared.Msg.ProposalJson, duplicate.Msg.ProposalJson) {
			t.Fatal("HTTP checkpoint retry changed snapshot", err)
		}
		var proposal workflow.CheckpointProposal
		if err := json.Unmarshal(prepared.Msg.ProposalJson, &proposal); err != nil {
			t.Fatal(err)
		}
		signed := proposal.Candidate.Checkpoint
		challenge := trust.ComputeCheckpointSigningDigest(tenant, signed.Epoch, signed.CheckpointDigest)
		sig, err := ecdsa.SignASN1(rand.Reader, leader, challenge[:])
		if err != nil {
			t.Fatal(err)
		}
		if err := authority.SignCheckpoint(&signed, trust.MemberSignature{ActorID: "authority", Signature: sig}); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := audits.AcceptCheckpoint(ctx, connect.NewRequest(&v1.AcceptCheckpointRequest{TenantId: tenant, AuthorityCheckpointJson: raw}))
		if err != nil || accepted.Msg.ReferenceSequence <= signed.ToSequence {
			t.Fatal("verified HTTP checkpoint acceptance", err)
		}
		if _, err := ordinaryAudit.AcceptCheckpoint(ctx, connect.NewRequest(&v1.AcceptCheckpointRequest{TenantId: tenant, AuthorityCheckpointJson: raw})); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatal("ordinary session accepted checkpoint", err)
		}
		lastCheckpoint = signed.CheckpointDigest.String()
	}
	checkpointPage, err := audits.ListCheckpoints(ctx, connect.NewRequest(&v1.ListCheckpointsRequest{TenantId: tenant, PageSize: 1}))
	if err != nil || len(checkpointPage.Msg.CheckpointRecordsJson) != 1 || checkpointPage.Msg.NextPageToken == "" {
		t.Fatal("checkpoint evidence pagination", err)
	}
	checkpointTail, err := audits.ListCheckpoints(ctx, connect.NewRequest(&v1.ListCheckpointsRequest{TenantId: tenant, PageSize: 1, PageToken: checkpointPage.Msg.NextPageToken}))
	if err != nil || len(checkpointTail.Msg.CheckpointRecordsJson) != 1 || checkpointTail.Msg.SnapshotEndSequence != checkpointPage.Msg.SnapshotEndSequence || checkpointTail.Msg.NextPageToken != "" {
		t.Fatal("checkpoint evidence continuation", err)
	}
	if _, err := audits.ListCheckpoints(ctx, connect.NewRequest(&v1.ListCheckpointsRequest{TenantId: tenant, PageToken: checkpointPage.Msg.NextPageToken + "x"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("forged checkpoint cursor", err)
	}
	if _, err := ordinaryAudit.ListCheckpoints(ctx, connect.NewRequest(&v1.ListCheckpointsRequest{TenantId: tenant})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary session obtained checkpoint proof", err)
	}
	anchored, err := audits.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant}))
	if err != nil || anchored.Msg.LatestCheckpointDigest != lastCheckpoint {
		t.Fatal("raw export missing accepted anchor", err)
	}
	frozen, err := audits.ExportHashChain(ctx, connect.NewRequest(&v1.ExportHashChainRequest{TenantId: tenant, EndSequence: end}))
	if err != nil || frozen.Msg.LatestCheckpointDigest != "" {
		t.Fatal("future checkpoint escaped frozen export boundary", err)
	}
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
	_ = wait()
	reviewAgain, err := reviews.GetChange(ctx, connect.NewRequest(&v1.GetChangeRequest{TenantId: tenant, RequestId: id}))
	if err != nil {
		t.Fatal(err)
	}
	reassessed := reviewAgain.Msg.Request
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
	observedEdges := []graph.Edge{}
	for _, edge := range data.Edges {
		if edge.Source == "user:compromised" && edge.Target == "role:admin" && edge.Kind == "ASSIGNED" {
			continue
		}
		observedEdges = append(observedEdges, edge)
	}
	data.Edges = observedEdges
	if _, err := store.IngestGraph(ctx, eventstore.GraphInput{TenantID: tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{9}).String(), FromRevision: 10, ToRevision: 11, Snapshot: &data, Complete: true}, key); err != nil {
		t.Fatal(err)
	}
	restoreInput := &v1.RestoreAccessRequest{TenantId: tenant, IncidentId: opened.Msg.Incident.IncidentId, TargetIdentity: "user:compromised", AccessToRestore: "role:admin", RequestedBy: "user:investigator", Justification: "Restore access through a new independent review after investigation", Mutation: mutation(0)}
	restored, err := containment.RestoreAccess(ctx, connect.NewRequest(restoreInput))
	if err != nil || restored.Msg.ChangeRequestId == "" {
		t.Fatal("real restoration request", err)
	}
	retriedRestore, err := containment.RestoreAccess(ctx, connect.NewRequest(restoreInput))
	if err != nil || retriedRestore.Msg.ChangeRequestId != restored.Msg.ChangeRequestId {
		t.Fatal("HTTP restoration retry duplicated request", err)
	}
	var restoreChange domain.Change
	for deadline := time.Now().Add(5 * time.Second); ; {
		restoreChange, err = store.ReadChange(ctx, tenant, restored.Msg.ChangeRequestId)
		if err != nil {
			t.Fatal(err)
		}
		if restoreChange.State == domain.AwaitingApproval {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restoration assessment did not require review", restoreChange.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if restoreChange.Decision.Quorum != 2 || len(restoreChange.Approvals) != 0 || restoreChange.Envelope.Intent.IncidentID != opened.Msg.Incident.IncidentId {
		t.Fatal("restoration bypassed fresh independent approvals")
	}
	linkedIncident, err := incidents.GetIncident(ctx, connect.NewRequest(&v1.GetIncidentRequest{TenantId: tenant, IncidentId: opened.Msg.Incident.IncidentId}))
	if err != nil || linkedIncident.Msg.Incident.Revision != 2 || len(linkedIncident.Msg.Incident.RestorationRequestIds) != 1 || linkedIncident.Msg.Incident.RestorationRequestIds[0] != restored.Msg.ChangeRequestId || len(linkedIncident.Msg.Incident.ActionsTaken) != 0 {
		t.Fatal("restoration was not durably linked", err)
	}
	restoreInput.RequestedBy = "user:requester"
	restoreInput.Mutation = mutation(0)
	if _, err := ordinaryContainment.RestoreAccess(ctx, connect.NewRequest(restoreInput)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("ordinary session bypassed restoration authorization", err)
	}
	window, err := changes.ListChanges(ctx, connect.NewRequest(&v1.ListChangesRequest{TenantId: tenant}))
	if err != nil || window.Msg.WatchCursor == "" {
		t.Fatal("list/watch cursor", err)
	}
	if _, err := reviews.HoldChange(ctx, connect.NewRequest(&v1.HoldChangeRequest{TenantId: tenant, RequestId: id, ActorId: "user:owner", Reason: "Internal investigation detail must remain private", Mutation: mutation(reassessed.Revision)})); err != nil {
		t.Fatal(err)
	}
	watch, err := changes.WatchChanges(ctx, connect.NewRequest(&v1.WatchChangesRequest{TenantId: tenant, Cursor: &v1.WatchCursor{AfterCursor: window.Msg.WatchCursor}}))
	if err != nil {
		t.Fatal(err)
	}
	if !watch.Receive() {
		t.Fatal("durable watch update missing", watch.Err())
	}
	frame := watch.Msg()
	if frame.Request == nil || frame.Request.RequestId != id || frame.Request.Status != "HELD" || frame.Request.ChangeDigest != "" || strings.Contains(strings.Join(frame.Request.DecisionReasons, " "), "Internal investigation") {
		t.Fatal("watch leaked reviewer detail or lost update")
	}
	resumeCursor := frame.Cursor
	if err := watch.Close(); err != nil {
		t.Fatal(err)
	}
	resume, err := changes.WatchChanges(ctx, connect.NewRequest(&v1.WatchChangesRequest{TenantId: tenant, Cursor: &v1.WatchCursor{AfterCursor: resumeCursor}}))
	if err != nil {
		t.Fatal(err)
	}
	if !resume.Receive() || !resume.Msg().Heartbeat || resume.Msg().Request != nil {
		t.Fatal("watch replayed already consumed revision", resume.Err())
	}
	_ = resume.Close()
	badWatch, err := changes.WatchChanges(ctx, connect.NewRequest(&v1.WatchChangesRequest{TenantId: tenant, Cursor: &v1.WatchCursor{AfterCursor: resumeCursor + "x"}}))
	if err == nil {
		if badWatch.Receive() || connect.CodeOf(badWatch.Err()) != connect.CodeInvalidArgument {
			t.Fatal("forged watch cursor accepted", badWatch.Err())
		}
		_ = badWatch.Close()
	}
	inline := ratchetv1connect.NewDecisionServiceClient(requester, base+"/api")
	exact := domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}
	objectDigest, err := canon.New().Digest(exact)
	if err != nil {
		t.Fatal(err)
	}
	decisionInput := &v1.DecisionRequest{Intent: &v1.ChangeIntent{TenantId: tenant, Kind: "SIM_ROLE_ASSIGN", TargetIdentity: exact.Target, RequestedAccess: exact.Access, RequestedBy: exact.Target}, AdmissionRequestId: uuid.NewString(), ExactObjectDigest: objectDigest.String(), TargetRevision: "11"}
	decision, err := inline.Decide(ctx, connect.NewRequest(decisionInput))
	if err != nil || decision.Msg.Outcome != "REQUIRE_APPROVAL" || decision.Msg.ExecutionAuthorized || len(decision.Msg.RequiredApproverGroups) != 0 || decision.Msg.PolicyBundleHash != "" {
		t.Fatal("authenticated inline policy/redaction", err)
	}
	decisionInput.Intent.RequestedBy = "user:investigator"
	if _, err := inline.Decide(ctx, connect.NewRequest(decisionInput)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("inline requester impersonation", err)
	}
	anonymousDecision := ratchetv1connect.NewDecisionServiceClient(client, base+"/api")
	if _, err := anonymousDecision.Decide(ctx, connect.NewRequest(decisionInput)); err == nil {
		t.Fatal("anonymous inline decision accepted")
	}
}
