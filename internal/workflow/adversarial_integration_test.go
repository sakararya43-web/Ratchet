//go:build integration

package workflow_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestAdversarialProofsAndConcurrentDistinctHumanQuorum(t *testing.T) {
	sys := setup(t)
	credentials := approval.NewCredentialStore()
	keys := map[string]*ecdsa.PrivateKey{}
	ids := map[string][]byte{}
	for _, actor := range []string{"user:sec1", "user:sec2"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys[actor], ids[actor] = key, []byte(uuid.NewString())
		if err := credentials.SaveCredential(sys.tenant, actor, "ephemeral cryptographic fixture", &webauthn.Credential{ID: ids[actor], PublicKey: pub}); err != nil {
			t.Fatal(err)
		}
	}
	verifier, err := approval.NewApprovalVerifier(credentials, "console.test", []string{"https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:admin"}, Justification: "Adversarial tier zero approval verification"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: created.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err := sys.store.ReadChange(sys.ctx, sys.tenant, created.ID)
	if err != nil || c.Decision.Quorum != 2 {
		t.Fatal("tier zero quorum", err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	valid := func() ports.ApprovalSubmission {
		return assertion(t, sys.tenant, actor.ID, c.Digest, keys[actor.ID], ids[actor.ID])
	}
	for _, name := range []string{"missing", "invalid", "wrong-context", "unknown-credential", "revoked"} {
		t.Run(name, func(t *testing.T) {
			proof := valid()
			switch name {
			case "missing":
				proof.Signature = nil
			case "invalid":
				proof.Signature = []byte("invalid")
			case "wrong-context":
				proof = assertion(t, sys.tenant, actor.ID, ports.Digest{42}, keys[actor.ID], ids[actor.ID])
			case "unknown-credential":
				proof.CredentialID = []byte("not enrolled")
			case "revoked":
				if err := credentials.RevokeCredential(sys.tenant, actor.ID, ids[actor.ID]); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := service.Approve(sys.ctx, actor, c.ID, uuid.New(), c.Revision, c.Digest, proof); !errors.Is(err, workflow.ErrPermission) {
				t.Fatal("invalid proof admitted", err)
			}
			current, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil || current.Revision != c.Revision || len(current.Approvals) != 0 {
				t.Fatal("invalid proof mutated approval state", err)
			}
		})
	}
	pub, err := x509.MarshalPKIXPublicKey(&keys[actor.ID].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.SaveCredential(sys.tenant, actor.ID, "restored fixture", &webauthn.Credential{ID: ids[actor.ID], PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	proof := valid()
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := service.Approve(sys.ctx, actor, c.ID, uuid.New(), c.Revision, c.Digest, proof); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("parallel signature counted more than once", successes.Load())
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || c.State != domain.AwaitingApproval || len(c.Approvals) != 1 {
		t.Fatal("one human met two-human quorum", err)
	}
	secondCredential := []byte(uuid.NewString())
	if err := credentials.SaveCredential(sys.tenant, actor.ID, "second passkey", &webauthn.Credential{ID: secondCredential, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(sys.ctx, actor, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, actor.ID, c.Digest, keys[actor.ID], secondCredential)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatal("second credential counted as another human", err)
	}
	actor.ID = "user:sec2"
	approved, err := service.Approve(sys.ctx, actor, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, actor.ID, c.Digest, keys[actor.ID], ids[actor.ID]))
	if err != nil || approved.State != domain.Approved || len(approved.Approvals) != 2 {
		t.Fatal("independent quorum failed", err)
	}
}
