package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

func tlsReader(t *testing.T, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(mustCert(t, caDER))
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
		if err != nil {
			t.Fatal(err)
		}
		return pair
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{issue("server", 2, x509.ExtKeyUsageServerAuth)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{issue("reader", 3, x509.ExtKeyUsageClientAuth)}}}
	t.Cleanup(transport.CloseIdleConnections)
	return server, &http.Client{Transport: transport, Timeout: 2 * time.Second}
}
func mustCert(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRealConnectTLSGraphPaginationImpactAndTenantBinding(t *testing.T) {
	registry, err := graph.NewRegistry(20 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s, err := graph.Build(20, graph.Data{Nodes: []graph.Node{{ID: "user:a", Type: "Human"}, {ID: "role:finance", Type: "Role"}, {ID: "role:admin", Type: "Role"}, {ID: "wallet", Type: "Resource", Tier: 0}, {ID: "reports", Type: "Resource", Tier: 2}}, Edges: []graph.Edge{{Source: "user:a", Target: "role:finance", Kind: "ASSIGNED"}, {Source: "role:finance", Target: "reports", Kind: "GRANTS", Action: "read"}, {Source: "role:admin", Target: "wallet", Kind: "GRANTS", Action: "sign"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish("tenant", s); err != nil {
		t.Fatal(err)
	}
	h, err := api.NewGraphHandler(registry, bytes.Repeat([]byte{2}, 32), map[string]api.Reader{"reader": {TenantID: "tenant", ActorID: "user:a"}})
	if err != nil {
		t.Fatal(err)
	}
	server, client := tlsReader(t, h)
	g := ratchetv1connect.NewGraphServiceClient(client, server.URL)
	impactClient := ratchetv1connect.NewImpactServiceClient(client, server.URL)
	first, err := g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "tenant", IdentityId: "user:a", PageSize: 1}))
	if err != nil || first.Msg.NextPageToken == "" {
		t.Fatalf("first page %v", err)
	}
	if first.Msg.GraphVersion != 20 {
		t.Fatal("missing graph version")
	}
	seen := map[string]bool{}
	page := first
	for {
		for _, n := range page.Msg.ReachableNodes {
			if seen[n.Id] {
				t.Fatal("node repeated across pages:", n.Id)
			}
			seen[n.Id] = true
		}
		if page.Msg.NextPageToken == "" {
			break
		}
		page, err = g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "tenant", IdentityId: "user:a", PageSize: 1, PageToken: page.Msg.NextPageToken}))
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 3 || !seen["reports"] {
		t.Fatalf("incomplete pagination: %v", seen)
	}
	details, err := g.GetNodeDetails(context.Background(), connect.NewRequest(&v1.GetNodeDetailsRequest{TenantId: "tenant", NodeId: "role:admin"}))
	if err != nil || len(details.Msg.OutgoingEdges) != 1 || details.Msg.OutgoingEdges[0].Properties["edge_id"] == "" {
		t.Fatalf("node provenance missing: %v", err)
	}
	neighbourhood, err := g.GetNeighbourhood(context.Background(), connect.NewRequest(&v1.GetNeighbourhoodRequest{TenantId: "tenant", NodeId: "wallet", Depth: 1}))
	if err != nil || len(neighbourhood.Msg.Nodes) != 2 || neighbourhood.Msg.Truncated {
		t.Fatalf("focused neighbourhood: %v", err)
	}
	paths, err := g.GetPathsToCritical(context.Background(), connect.NewRequest(&v1.GetPathsToCriticalRequest{TenantId: "tenant", IdentityId: "user:a"}))
	if err != nil || len(paths.Msg.Routes) != 0 || paths.Msg.GraphVersion != 20 {
		t.Fatalf("paths against current generation: %v", err)
	}
	if _, err := g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "other", IdentityId: "user:a"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("tenant binding: %v", err)
	}
	if _, err := g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "tenant", IdentityId: "user:a", MinGraphVersion: 21})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("stale graph: %v", err)
	}
	response, err := impactClient.SimulateChange(context.Background(), connect.NewRequest(&v1.SimulateChangeRequest{TenantId: "tenant", Kind: "ROLE_ASSIGN", TargetIdentity: "user:a", RequestedAccess: "role:admin", RequestedBy: "user:a"}))
	if err != nil {
		t.Fatal(err)
	}
	if response.Msg.Impact.GraphVersion != 20 || len(response.Msg.Impact.NewResources) != 1 || response.Msg.Impact.NewResources[0].Id != "wallet" || response.Msg.Impact.NewTier0PathsCount == 0 {
		t.Fatalf("impact=%+v", response.Msg.Impact)
	}
	if _, err := impactClient.SimulateChange(context.Background(), connect.NewRequest(&v1.SimulateChangeRequest{TenantId: "tenant", Kind: "ROLE_ASSIGN", TargetIdentity: "user:a", RequestedAccess: "role:admin", RequestedBy: "forged"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("forged actor: %v", err)
	}
	before, _ := s.Reach("user:a")
	if before.ByTier[0] != 0 {
		t.Fatal("simulation mutated published graph")
	}
	newGeneration, err := s.Overlay(21, graph.Delta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Publish("tenant", newGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "tenant", IdentityId: "user:a", PageSize: 1, PageToken: first.Msg.NextPageToken})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("cursor crossed generations: %v", err)
	}
	if _, err := g.GetReach(context.Background(), connect.NewRequest(&v1.GetReachRequest{TenantId: "tenant", IdentityId: "user:a", PageToken: "forged.cursor"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("forged cursor: %v", err)
	}
}

func TestGraphHTTPHeaderIsNotAuthentication(t *testing.T) {
	registry, err := graph.NewRegistry(time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	h, err := api.NewGraphHandler(registry, bytes.Repeat([]byte{1}, 32), map[string]api.Reader{"reader": {TenantID: "tenant", ActorID: "user:a"}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/ratchet.v1.GraphService/GetReach", nil)
	r.Header.Set("X-Actor-ID", "user:a")
	r.Header.Set("X-Tenant-ID", "tenant")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("headers authenticated the caller")
	}
}
