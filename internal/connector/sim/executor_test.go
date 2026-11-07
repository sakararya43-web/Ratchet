package sim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	target "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func TestExecutorDurableResultRepublishAndReadOnlyReconciliation(t *testing.T) {
	ctx := context.Background()
	pub, core := keys(t)
	_, edge := keys(t)
	store, err := target.NewStore(filepath.Join(t.TempDir(), "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	routes := simserver.NewServer(store, "test-token").Routes()
	var writes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			writes.Add(1)
		}
		routes.ServeHTTP(w, r)
	}))
	defer server.Close()
	dir := t.TempDir()
	adapter := NewAdapter(server.URL, "test-token", "tenant-exchange-demo", "connector-sim-01")
	var published [][]byte
	failPublish := true
	publisher := func(_ context.Context, subject, id string, raw []byte) error {
		if subject != "ratchet.tenant-exchange-demo.exec.results" || id == "" {
			t.Fatal("wrong result route")
		}
		published = append(published, append([]byte{}, raw...))
		if failPublish {
			return errors.New("lost publish acknowledgement")
		}
		return nil
	}
	open := func() *Executor {
		e, err := NewExecutor("tenant-exchange-demo", "connector-sim-01", dir, pub, edge, adapter, publisher)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	command := validCommand(t)
	command.Envelope.Intent.Target = "user:sec-lead-1"
	command.BeforeRoles = []string{"role:security-lead"}
	command.ExpectedRoles = []string{"role:finance-analyst", "role:security-lead"}
	command.EnvelopeDigest, err = canon.New().Digest(command.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	raw := signedCommand(t, core, command)
	if err = open().Handle(ctx, raw); err == nil {
		t.Fatal("lost publish acknowledgement was hidden")
	}
	failPublish = false
	if err = open().Handle(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 || store.GetState().Revision != 1001 || !bytes.Equal(published[0], published[1]) {
		t.Fatal("restart/redelivery repeated target effect or changed result")
	}
	var result workflow.ExecutionResult
	if err = json.Unmarshal(published[1], &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || !result.ReadBackVerified || result.AppliedAt.IsZero() {
		t.Fatal("real application missing", result)
	}
	observation, err := canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{command.Tenant, command.Envelope.Intent.Target, command.ExpectedRoles, 1001, result.ObservedAt})
	if err != nil || observation != result.ObservationDigest {
		t.Fatal("core observation contract diverged")
	}
	signature := result.Signature
	result.Signature = nil
	digest, err := protocolDigest("RATCHET_EXEC_RESULT_V1", result)
	if err != nil || !ed25519.Verify(edge.Public().(ed25519.PublicKey), digest[:], signature) {
		t.Fatal("unsigned result")
	}
	command.VerifyOnly = true
	command.MessageID = uuid.NewString()
	if err = open().Handle(ctx, signedCommand(t, core, command)); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("verify-only repeated write")
	}
	// A signed query for an unexecuted command proves unchanged state and never
	// supplies an invented application timestamp.
	query := validCommand(t)
	query.ExpectedRevision = 1001
	query.VerifyOnly = true
	if err = open().Handle(ctx, signedCommand(t, core, query)); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(published[len(published)-1], &result); err != nil {
		t.Fatal(err)
	}
	if result.Success || !result.ReadBackVerified || !result.AppliedAt.IsZero() || writes.Load() != 1 {
		t.Fatal("read-only query fabricated execution", result)
	}
	command.VerifyOnly = false
	command.MessageID = uuid.NewString()
	command.ExpectedRoles = []string{"role:exchange-admin"}
	command.Envelope.Intent.Access = "role:exchange-admin"
	command.EnvelopeDigest, err = canon.New().Digest(command.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = open().Handle(ctx, signedCommand(t, core, command)); err == nil {
		t.Fatal("reused command identity accepted")
	}
	if writes.Load() != 1 {
		t.Fatal("conflicting identity reached target")
	}

	revoke := validCommand(t)
	revoke.Envelope.Intent.Kind = "ROLE_REVOKE"
	revoke.Envelope.Intent.Target = "user:sec-lead-1"
	revoke.ExpectedRevision = 1001
	revoke.BeforeRoles = []string{"role:finance-analyst", "role:security-lead"}
	revoke.ExpectedRoles = []string{"role:security-lead"}
	revoke.EnvelopeDigest, err = canon.New().Digest(revoke.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = open().Handle(ctx, signedCommand(t, core, revoke)); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(published[len(published)-1], &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || !result.ReadBackVerified || result.ObservedRevision != 1002 || writes.Load() != 2 {
		t.Fatal("real role revocation failed", result)
	}
}
func TestExecutorRecoversTargetReceiptAfterLostReadback(t *testing.T) {
	ctx := context.Background()
	pub, core := keys(t)
	_, edge := keys(t)
	targetPath := filepath.Join(t.TempDir(), "target.json")
	store, err := target.NewStore(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	routes := simserver.NewServer(store, "test-token").Routes()
	var writes atomic.Int64
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && unavailable.Load() {
			http.Error(w, "read outage", http.StatusServiceUnavailable)
			return
		}
		routes.ServeHTTP(w, r)
		if r.Method == "POST" {
			writes.Add(1)
			unavailable.Store(true)
		}
	}))
	dir := t.TempDir()
	command := validCommand(t)
	var result workflow.ExecutionResult
	publish := func(_ context.Context, _, _ string, raw []byte) error { return json.Unmarshal(raw, &result) }
	e, err := NewExecutor(command.Tenant, command.Connector, dir, pub, edge, NewAdapter(server.URL, "test-token", command.Tenant, command.Connector), publish)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Handle(ctx, signedCommand(t, core, command)); err == nil {
		t.Fatal("read outage acknowledged")
	}
	if writes.Load() != 1 {
		t.Fatal("target did not really commit")
	}
	server.Close()
	reopened, err := target.NewStore(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	restoredRoutes := simserver.NewServer(reopened, "test-token").Routes()
	restarted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			writes.Add(1)
		}
		restoredRoutes.ServeHTTP(w, r)
	}))
	defer restarted.Close()
	e, err = NewExecutor(command.Tenant, command.Connector, dir, pub, edge, NewAdapter(restarted.URL, "test-token", command.Tenant, command.Connector), publish)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Handle(ctx, signedCommand(t, core, command)); err != nil {
		t.Fatal(err)
	}
	receipt := reopened.GetState().CommandReceipts[command.CommandID]
	if writes.Load() != 1 || !result.Success || !result.ReadBackVerified || !result.AppliedAt.Equal(receipt.AppliedAt) {
		t.Fatal("target receipt recovery was not exact", result)
	}
}
func TestExecutorStaleAndExpiredCommandsNeverWrite(t *testing.T) {
	for _, kind := range []string{"stale", "expired", "verify-only"} {
		t.Run(kind, func(t *testing.T) {
			pub, core := keys(t)
			_, edge := keys(t)
			store, err := target.NewStore(filepath.Join(t.TempDir(), "target.json"))
			if err != nil {
				t.Fatal(err)
			}
			routes := simserver.NewServer(store, "test-token").Routes()
			var writes atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					writes.Add(1)
				}
				routes.ServeHTTP(w, r)
			}))
			defer server.Close()
			command := validCommand(t)
			switch kind {
			case "stale":
				command.ExpectedRevision = 999
			case "expired":
				command.DispatchedAt = time.Now().Add(-time.Hour)
				command.Deadline = time.Now().Add(-time.Second)
				command.Envelope.ExpiresAt = command.Deadline
				command.EnvelopeDigest, err = canon.New().Digest(command.Envelope)
				if err != nil {
					t.Fatal(err)
				}
			case "verify-only":
				command.VerifyOnly = true
			}
			var result workflow.ExecutionResult
			e, err := NewExecutor(command.Tenant, command.Connector, t.TempDir(), pub, edge, NewAdapter(server.URL, "test-token", command.Tenant, command.Connector), func(_ context.Context, _, _ string, raw []byte) error { return json.Unmarshal(raw, &result) })
			if err != nil {
				t.Fatal(err)
			}
			if err = e.Handle(context.Background(), signedCommand(t, core, command)); err != nil {
				t.Fatal(err)
			}
			if writes.Load() != 0 || store.GetState().Revision != 1000 || result.Success || !result.AppliedAt.IsZero() {
				t.Fatal("refusal/query mutated target or invented application")
			}
			if kind == "stale" && result.ReadBackVerified {
				t.Fatal("changed preimage claimed unchanged")
			}
		})
	}
}
