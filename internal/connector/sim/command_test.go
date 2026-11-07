package sim

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func signedCommand(t *testing.T, key ed25519.PrivateKey, c workflow.PreparedCommand) []byte {
	t.Helper()
	c.Signature = nil
	d, err := protocolDigest("RATCHET_EXEC_COMMAND_V1", c)
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = ed25519.Sign(key, d[:])
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func validCommand(t *testing.T) workflow.PreparedCommand {
	t.Helper()
	now := time.Now().UTC()
	digest, _ := canon.New().Digest("context")
	e := &domain.Envelope{FormatVersion: 2, TenantID: "tenant-exchange-demo", RequestID: uuid.NewString(), Revision: 3, Requester: "user:rahul-assistant", Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:rahul-assistant", Access: "role:finance-analyst"}, GraphVersion: 1, ImpactDigest: digest, PolicyDigest: digest, PrivateDigest: digest, PrivateReference: uuid.NewString(), ExpiresAt: now.Add(5 * time.Minute)}
	bound, err := canon.New().Digest(e)
	if err != nil {
		t.Fatal(err)
	}
	return workflow.PreparedCommand{SchemaVersion: 1, Tenant: e.TenantID, Connector: "connector-sim-01", MessageID: uuid.NewString(), CommandID: uuid.NewString(), RequestID: e.RequestID, CorrelationID: uuid.NewString(), ExpectedRevision: 1000, BeforeRoles: []string{}, ExpectedRoles: []string{e.Intent.Access}, Envelope: e, EnvelopeDigest: bound, Deadline: e.ExpiresAt, DispatchedAt: now}
}
func TestCommandAuthenticationRefusesMalformedAndUnboundInputs(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := validCommand(t)
	raw := signedCommand(t, key, base)
	if _, err := AuthenticateCommand(raw, base.Tenant, base.Connector, pub, time.Now()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*workflow.PreparedCommand){
		"tenant": func(c *workflow.PreparedCommand) { c.Tenant = "other" }, "connector": func(c *workflow.PreparedCommand) { c.Connector = "other" }, "schema": func(c *workflow.PreparedCommand) { c.SchemaVersion = 2 }, "id": func(c *workflow.PreparedCommand) { c.CommandID = "invented" }, "revision": func(c *workflow.PreparedCommand) { c.ExpectedRevision = 0 }, "context": func(c *workflow.PreparedCommand) { c.Envelope.Intent.Access = "role:exchange-admin" }, "roles": func(c *workflow.PreparedCommand) { c.ExpectedRoles = []string{"role:exchange-admin"} }, "purpose": func(c *workflow.PreparedCommand) { c.Purpose = "EXPIRE_GRANT" }, "deadline": func(c *workflow.PreparedCommand) { c.Deadline = time.Now().Add(-time.Second) }, "kind": func(c *workflow.PreparedCommand) { c.Envelope.Intent.Kind = "UNKNOWN" }, "future": func(c *workflow.PreparedCommand) { c.DispatchedAt = time.Now().Add(time.Hour) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var c workflow.PreparedCommand
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			mutate(&c)
			if _, err := AuthenticateCommand(signedCommand(t, key, c), base.Tenant, base.Connector, pub, time.Now()); err == nil {
				t.Fatal("invalid signed command accepted")
			}
		})
	}
	for name, bad := range map[string][]byte{"unsigned": mustUnsigned(t, base), "trailing": append(append([]byte{}, raw...), []byte(" {}")...), "unknown": append([]byte(`{"unexpected":1,`), raw[1:]...), "duplicate": append([]byte(`{"schema_version":1,`), raw[1:]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := AuthenticateCommand(bad, base.Tenant, base.Connector, pub, time.Now()); err == nil {
				t.Fatal("invalid wire command accepted")
			}
		})
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateCommand(signedCommand(t, other, base), base.Tenant, base.Connector, pub, time.Now()); err == nil {
		t.Fatal("untrusted signer")
	}
	base.VerifyOnly = true
	if _, err := AuthenticateCommand(signedCommand(t, key, base), base.Tenant, base.Connector, pub, base.Deadline.Add(time.Hour)); err != nil {
		t.Fatal("read-only recovery must survive deadline", err)
	}
}
func mustUnsigned(t *testing.T, c workflow.PreparedCommand) []byte {
	t.Helper()
	c.Signature = nil
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
