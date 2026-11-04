//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
	"google.golang.org/protobuf/encoding/protojson"
)

type listenerAddress struct{ ready chan string }

func (w listenerAddress) Write(p []byte) (int, error) {
	line := string(p)
	if value, ok := strings.CutPrefix(line, "core health listener: "); ok {
		select {
		case w.ready <- strings.TrimSpace(value):
		default:
		}
	}
	return len(p), nil
}

func TestGraphRuntimeRealBrokerDatabaseAndMutualTLS(t *testing.T) {
	if os.Getenv("RATCHET_DATABASE_DSN") == "" || os.Getenv("RATCHET_MIGRATION_DSN") == "" {
		t.Fatal("real runtime/migration DSNs required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := eventstore.Migrate(ctx, os.Getenv("RATCHET_MIGRATION_DSN")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath, client := runtimePKI(t, dir)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "runtime_" + uuid.NewString()
	natsURL := os.Getenv("RATCHET_NATS_URL")
	if natsURL == "" {
		natsURL = "nats://127.0.0.1:54222"
	}
	config := map[string]any{"graph_key_hex": hex.EncodeToString(bytes.Repeat([]byte{33}, 32)), "cursor_key_hex": hex.EncodeToString(bytes.Repeat([]byte{44}, 32)), "nats_url": natsURL, "server_cert": certPath, "server_key": keyPath, "client_ca": caPath, "readers": map[string]any{"reader": map[string]string{"tenant_id": tenant, "actor_id": "user:operator"}}, "connectors": []map[string]string{{"tenant_id": tenant, "connector_id": "source", "public_key_hex": hex.EncodeToString(public)}}}
	rawConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, rawConfig, 0600); err != nil {
		t.Fatal(err)
	}
	runtimeCtx, stop := context.WithCancel(ctx)
	address := listenerAddress{make(chan string, 1)}
	finished := make(chan error, 1)
	go func() {
		finished <- runGraph(runtimeCtx, []string{"--config", configPath, "--listen", "127.0.0.1:0"}, address)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("runtime did not stop")
		}
	})
	var host string
	select {
	case host = <-address.ready:
	case err := <-finished:
		t.Fatalf("runtime startup: %v", err)
	case <-ctx.Done():
		t.Fatal("runtime did not listen")
	}
	broker, err := bus.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	message := &v1.SignedGraphSync{Envelope: &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: tenant, ConnectorId: "source", MessageId: uuid.NewString(), CorrelationId: uuid.NewString(), SourceRevision: 10}, Payload: &v1.SignedGraphSync_Snapshot{Snapshot: &v1.GraphSnapshot{TenantId: tenant, ConnectorId: "source", SourceRevision: 10, Complete: true, Nodes: []*v1.GraphNode{{Id: "user:a", Type: "Human"}, {Id: "role:admin", Type: "Role"}, {Id: "wallet", Type: "Resource", Tier: 0}}, Edges: []*v1.GraphEdge{{Source: "role:admin", Target: "wallet", Kind: "GRANTS", Action: "sign"}}}}}
	digest, err := bus.SyncSigningDigest(canon.New(), message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(private, digest[:])
	wire, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Publish(ctx, "ratchet."+tenant+".ingest.sync", message.Envelope.MessageId, wire); err != nil {
		t.Fatal(err)
	}
	g := ratchetv1connect.NewGraphServiceClient(client, "https://"+host+"/api")
	impact := ratchetv1connect.NewImpactServiceClient(client, "https://"+host+"/api")
	var version int64
	for ctx.Err() == nil {
		node, err := g.GetNodeDetails(ctx, connect.NewRequest(&v1.GetNodeDetailsRequest{TenantId: tenant, NodeId: "wallet", MinGraphVersion: 1}))
		if err == nil {
			version = node.Msg.GraphVersion
			break
		}
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatal(err)
		}
	}
	if version == 0 {
		t.Fatal("signed sync did not appear through real API")
	}
	result, err := impact.SimulateChange(ctx, connect.NewRequest(&v1.SimulateChangeRequest{TenantId: tenant, Kind: "ROLE_ASSIGN", TargetIdentity: "user:a", RequestedAccess: "role:admin", RequestedBy: "user:operator"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Msg.Impact.NewResources) != 1 || result.Msg.Impact.GraphVersion != version {
		t.Fatal("runtime impact missing")
	}
	after, err := g.GetReach(ctx, connect.NewRequest(&v1.GetReachRequest{TenantId: tenant, IdentityId: "user:a"}))
	if err != nil || after.Msg.GraphVersion != version || after.Msg.ReachByTier["0"] != 0 {
		t.Fatal("simulation changed persisted graph")
	}
	response, err := client.Get("https://" + host + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("real backlog metrics unavailable")
	}
}

func runtimePKI(t *testing.T, dir string) (string, string, string, *http.Client) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runtime-root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	}
	serverCert, serverKey := issue("server", 2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issue("reader", 3, x509.ExtKeyUsageClientAuth)
	pair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, caPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, "ca.pem")
	for path, content := range map[string][]byte{certPath: serverCert, keyPath: serverKey, caPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}}
	t.Cleanup(transport.CloseIdleConnections)
	return certPath, keyPath, caPath, &http.Client{Transport: transport, Timeout: 3 * time.Second}
}
