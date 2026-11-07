//go:build integration

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	target "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	simserver "github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestExecutableAuthenticatedCASAndCrashRecovery(t *testing.T) {
	address := os.Getenv("RATCHET_NATS_URL")
	if address == "" {
		t.Skip("real JetStream required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	broker, err := bus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	nc, err := nats.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant-exchange-demo"
	connectorID := "process-" + uuid.NewString()
	if err = broker.EnsureTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err = broker.EnsureExecution(ctx, tenant, connectorID); err != nil {
		t.Fatal(err)
	}
	stream := bus.StreamName(tenant, "EXEC_"+bus.StreamName(connectorID, "KEY"))
	defer func() { _ = js.DeleteStream(stream) }()
	subscription, err := nc.SubscribeSync("ratchet." + tenant + ".exec.results")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = subscription.Unsubscribe() }()
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pub, core, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edge, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"core.pub": pub, "edge.key": edge} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(hex.EncodeToString(value)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "connector")
	build := exec.CommandContext(ctx, "go", "build", "-race", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("actual connector build: %v %s", err, output)
	}
	store, err := target.NewStore(filepath.Join(dir, "target.json"))
	if err != nil {
		t.Fatal(err)
	}
	routes := simserver.NewServer(store, "process-test-token").Routes()
	var writes atomic.Int64
	var failRead atomic.Bool
	var dropAfterWrite atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && failRead.Load() {
			http.Error(w, "read outage", http.StatusServiceUnavailable)
			return
		}
		routes.ServeHTTP(w, r)
		if r.Method == "POST" {
			writes.Add(1)
			if dropAfterWrite.Load() {
				failRead.Store(true)
			}
		}
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthAddress := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	var process *exec.Cmd
	stop := func() {
		if process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
			process = nil
		}
	}
	defer stop()
	start := func() {
		process = exec.CommandContext(ctx, binary, "--tenant", tenant, "--id", connectorID, "--target", server.URL, "--nats", address, "--key", filepath.Join(dir, "edge.key"), "--core-key", filepath.Join(dir, "core.pub"), "--state", filepath.Join(dir, "commands"), "--cursor", filepath.Join(dir, "cursor.json"), "--interval", "100ms", "--health-listen", healthAddress)
		process.Env = append(os.Environ(), "SIM_BROKER_TOKEN=process-test-token")
		process.Stdout = io.Discard
		process.Stderr = io.Discard
		if err = process.Start(); err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Timeout: time.Second}
		ready := false
		for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
			response, err := client.Get("http://" + healthAddress + "/readyz")
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					ready = true
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			t.Fatal("actual executable readiness unavailable")
		}
	}
	start()
	digest, err := canon.New().Digest("process-context")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope := &domain.Envelope{FormatVersion: 2, TenantID: tenant, RequestID: uuid.NewString(), Requester: "user:rahul", Revision: 3, GraphVersion: 1, Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:rahul-assistant", Access: "role:finance-analyst"}, ImpactDigest: digest, PolicyDigest: digest, PrivateDigest: digest, PrivateReference: uuid.NewString(), ExpiresAt: now.Add(5 * time.Minute)}
	command := workflow.PreparedCommand{MessageID: uuid.NewString(), SchemaVersion: 1, Tenant: tenant, Connector: connectorID, CommandID: uuid.NewString(), RequestID: envelope.RequestID, CorrelationID: uuid.NewString(), ExpectedRevision: 1000, BeforeRoles: []string{}, ExpectedRoles: []string{envelope.Intent.Access}, Envelope: envelope, DispatchedAt: now, Deadline: envelope.ExpiresAt}
	rebind := func(c *workflow.PreparedCommand) {
		c.EnvelopeDigest, err = canon.New().Digest(c.Envelope)
		if err != nil {
			t.Fatal(err)
		}
	}
	rebind(&command)
	encode := func(c workflow.PreparedCommand, sign bool) []byte {
		c.Signature = nil
		if sign {
			d, err := canon.New().Digest(struct {
				Domain string `json:"domain"`
				Body   any    `json:"body"`
			}{"RATCHET_EXEC_COMMAND_V1", c})
			if err != nil {
				t.Fatal(err)
			}
			c.Signature = ed25519.Sign(core, d[:])
		}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sent := uint64(0)
	send := func(c workflow.PreparedCommand, sign bool) {
		if err = broker.Publish(ctx, "ratchet."+tenant+".exec."+connectorID, uuid.NewString(), encode(c, sign)); err != nil {
			t.Fatal(err)
		}
		sent++
	}
	waitAck := func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			info, err := js.ConsumerInfo(stream, "native-commands-v1")
			if err == nil && info.Delivered.Consumer >= sent && info.NumAckPending == 0 && info.NumPending == 0 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("executable did not durably acknowledge input")
	}
	receive := func(id string) workflow.ExecutionResult {
		t.Helper()
		for {
			msg, err := subscription.NextMsgWithContext(ctx)
			if err != nil {
				t.Fatal("missing executable result", err)
			}
			var r workflow.ExecutionResult
			if json.Unmarshal(msg.Data, &r) == nil && r.CommandID == id {
				return r
			}
		}
	}
	send(command, false)
	waitAck()
	if writes.Load() != 0 {
		t.Fatal("unsigned executable input wrote target")
	}
	unknown := command
	copyEnvelope := *command.Envelope
	unknown.Envelope = &copyEnvelope
	unknown.Envelope.Intent.Kind = "UNKNOWN"
	rebind(&unknown)
	send(unknown, true)
	waitAck()
	if writes.Load() != 0 {
		t.Fatal("unknown action defaulted to write")
	}
	query := command
	query.VerifyOnly = true
	query.MessageID = uuid.NewString()
	send(query, true)
	unchanged := receive(query.CommandID)
	waitAck()
	if unchanged.Success || !unchanged.ReadBackVerified || !unchanged.AppliedAt.IsZero() || writes.Load() != 0 {
		t.Fatal("executable verification issued a write")
	}
	stale := command
	stale.CommandID = uuid.NewString()
	stale.MessageID = uuid.NewString()
	stale.ExpectedRevision = 999
	send(stale, true)
	uncertain := receive(stale.CommandID)
	waitAck()
	if uncertain.ReadBackVerified || writes.Load() != 0 {
		t.Fatal("stale precondition was silently rebased")
	}
	// The actual process commits at the target, loses read-back and dies before a
	// result exists. JetStream redelivery must recover that same durable receipt.
	dropAfterWrite.Store(true)
	send(command, true)
	deadline := time.Now().Add(10 * time.Second)
	for writes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if writes.Load() != 1 {
		t.Fatal("actual target write not observed")
	}
	time.Sleep(200 * time.Millisecond)
	stop()
	dropAfterWrite.Store(false)
	failRead.Store(false)
	start()
	applied := receive(command.CommandID)
	waitAck()
	if !applied.Success || !applied.ReadBackVerified || writes.Load() != 1 || store.GetState().Revision != 1001 {
		t.Fatal("process crash recovery repeated or lost application", applied)
	}
	receipt := store.GetState().CommandReceipts[command.CommandID]
	if !applied.AppliedAt.Equal(receipt.AppliedAt) {
		t.Fatal("recovery invented timestamp")
	}
	stop()
	start()
	send(command, true)
	waitAck()
	query.MessageID = uuid.NewString()
	send(query, true)
	reconciled := receive(query.CommandID)
	waitAck()
	if !reconciled.Success || !reconciled.ReadBackVerified || !reconciled.AppliedAt.Equal(applied.AppliedAt) || writes.Load() != 1 {
		t.Fatal("restart/reconciliation was not read-only")
	}
	t.Log("real executable + JetStream: unsigned/unknown refusal, read-only query, stale preimage, crash receipt recovery and restart dedup passed")
}
