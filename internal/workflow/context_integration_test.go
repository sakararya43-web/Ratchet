//go:build integration

package workflow_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func replaceGraph(t *testing.T, sys system, data graph.Data) {
	t.Helper()
	if _, err := sys.store.IngestGraph(sys.ctx, eventstore.GraphInput{TenantID: sys.tenant, ConnectorID: "source", MessageID: uuid.New(), CorrelationID: uuid.NewString(), WireDigest: (ports.Digest{7}).String(), FromRevision: 10, ToRevision: 11, Complete: true, Snapshot: &data}, sys.key); err != nil {
		t.Fatal(err)
	}
}
func TestGraphPolicyAndCredentialChangesPreventApprovedDispatch(t *testing.T) {
	for _, kind := range []string{"new-requester-control", "new-policy", "new-registry-in-another-instance", "revoked-credential"} {
		t.Run(kind, func(t *testing.T) {
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
			id := []byte(uuid.NewString())
			if err := credentials.SaveCredential(sys.tenant, "user:owner", "ephemeral fixture", &webauthn.Credential{ID: id, PublicKey: pub}); err != nil {
				t.Fatal(err)
			}
			verifier, err := approval.NewApprovalVerifier(credentials, "console.test", []string{"https://console.test"})
			if err != nil {
				t.Fatal(err)
			}
			execution, _ := signCapability(t, sys.tenant)
			service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant}, execution)
			if err != nil {
				t.Fatal(err)
			}
			c, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "Review must remain independent at execution"})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
				t.Fatal(err)
			}
			c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			c, err = service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}, c.ID, uuid.New(), c.Revision, c.Digest, assertion(t, sys.tenant, "user:owner", c.Digest, key, id))
			if err != nil || c.State != domain.Approved {
				t.Fatal(err)
			}
			switch kind {
			case "new-requester-control":
				snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
				if err != nil {
					t.Fatal(err)
				}
				data := snapshot.Data()
				data.Edges = append(data.Edges, graph.Edge{Source: "user:requester", Target: "user:owner", Kind: "CAN_ADMINISTER"})
				replaceGraph(t, sys, data)
			case "new-policy":
				modules := map[string]string{}
				for _, name := range []string{"change.rego", "authz.rego"} {
					raw, err := os.ReadFile("../../policies/" + name)
					if err != nil {
						t.Fatal(err)
					}
					modules[name] = string(raw)
				}
				b, err := sys.authority.ProposeBundle(sys.tenant, "1.1.0", "changed policy context", modules, map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				d := trust.ComputePolicySigningDigest(sys.tenant, 1, b.BundleDigest)
				sig, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, d[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := sys.authority.SignProposal(b.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: sig}); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				manager := policy.Manager{Store: sys.store, Engine: sys.engine, Authority: sys.authority, Root: sys.root, Tenant: sys.tenant}
				if err := manager.Activate(sys.ctx, raw); err != nil {
					t.Fatal(err)
				}
			case "new-registry-in-another-instance":
				g, err := sys.authority.GetGenesis()
				if err != nil {
					t.Fatal(err)
				}
				p, err := sys.authority.ProposeRegistryChange(sys.tenant, 1, 1, g.Members)
				if err != nil {
					t.Fatal(err)
				}
				d := trust.ComputeRegistrySigningDigest(sys.tenant, 1, 2, p.ProposalDigest)
				sig, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, d[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := sys.authority.SignRegistryProposal(p.ProposalID, trust.MemberSignature{ActorID: "authority-leader", Signature: sig}); err != nil {
					t.Fatal(err)
				}
				if _, err := sys.authority.ActivateRegistryProposal(p.ProposalID); err != nil {
					t.Fatal(err)
				}
				other := policy.Manager{Store: sys.store, Engine: policy.NewEngine(), Authority: sys.authority, Root: sys.root, Tenant: sys.tenant}
				if err := other.RefreshRegistry(sys.ctx); err != nil {
					t.Fatal(err)
				}
				if err := service.PolicyReady(sys.ctx); !errors.Is(err, workflow.ErrDependency) {
					t.Fatal("stale instance reported a ready policy", err)
				}
			case "revoked-credential":
				if err := credentials.RevokeCredential(sys.tenant, "user:owner", id); err != nil {
					t.Fatal(err)
				}
			}
			if err := service.Guard(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: c.Revision, Operation: "guard"}); err != nil {
				t.Fatal(err)
			}
			held, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
			if err != nil || held.State != domain.Held || len(held.Approvals) != 0 || held.Envelope != nil {
				t.Fatal("stale proof retained", err)
			}
			if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
				var writes int
				if err := tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.execution_attempts WHERE tenant_id=$1`, sys.tenant).Scan(&writes); err != nil {
					return err
				}
				if writes != 0 {
					t.Fatal("changed authorization dispatched")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRequesterControlledReviewerAndOrdinaryWithdrawalWeakeningAreRefused(t *testing.T) {
	sys := setup(t)
	snapshot, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := snapshot.Data()
	data.Nodes = append(data.Nodes, graph.Node{ID: "service:bridge", Type: "ServiceAccount"}, graph.Node{ID: "safeguard:withdrawal", Type: "Safeguard", Tier: 0, Properties: map[string]string{"guard_kind": "withdrawal_threshold_v1", "required_checks": "2", "threshold_usd": "10000"}})
	data.Edges = append(data.Edges, graph.Edge{Source: "user:requester", Target: "service:bridge", Kind: "CAN_ASSUME"}, graph.Edge{Source: "service:bridge", Target: "user:owner", Kind: "CAN_ADMINISTER"}, graph.Edge{Source: "wallet", Target: "safeguard:withdrawal", Kind: "PROTECTED_BY"})
	replaceGraph(t, sys, data)
	credentials := approval.NewCredentialStore()
	verifier, err := approval.NewApprovalVerifier(credentials, "console.test", []string{"https://console.test"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, verifier, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	c, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:requester", Access: "role:finance"}, Justification: "An inherited takeover must not enable self approval"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: c.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	c, err = sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"user:requester", "user:owner"} {
		if _, err := service.Approve(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: actor}, c.ID, uuid.New(), c.Revision, c.Digest, ports.ApprovalSubmission{}); !errors.Is(err, workflow.ErrPermission) {
			t.Fatal("requester or controlled reviewer admitted", actor, err)
		}
	}
	unchanged, err := sys.store.ReadChange(sys.ctx, sys.tenant, c.ID)
	if err != nil || unchanged.Revision != c.Revision || len(unchanged.Approvals) != 0 {
		t.Fatal("refused approval advanced state", err)
	}
	weakening, err := service.Submit(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: domain.Intent{Kind: "MODIFY_SAFEGUARD", Target: "safeguard:withdrawal", Parameters: map[string]string{"required_checks": "1"}}, Justification: "Ordinary requests cannot weaken withdrawal quorum"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Assess(sys.ctx, workflow.JobArgs{Tenant: sys.tenant, Request: weakening.ID, Revision: 1, Operation: "assess"}); err != nil {
		t.Fatal(err)
	}
	rejected, err := sys.store.ReadChange(sys.ctx, sys.tenant, weakening.ID)
	if err != nil || rejected.State != domain.Rejected {
		t.Fatal("ordinary withdrawal weakening was not rejected", err)
	}
}
