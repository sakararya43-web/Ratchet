//go:build peerintegration

package conformance_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/connector/conformance"
	peer "github.com/sakararya43-web/Ratchet/internal/connector/k8s"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// These are acceptance assertions against the unmodified real peer, not
// expected-failure tests or a replacement webhook. Run in a combined checkout.
func TestPeerKubernetesAdmissionConformance(t *testing.T) {
	request := func(role string) *peer.AdmissionRequest {
		return &peer.AdmissionRequest{UID: "actual-admission-uid", Operation: "CREATE", Kind: map[string]string{"group": "rbac.authorization.k8s.io", "version": "v1", "kind": "RoleBinding"}, Resource: map[string]string{"group": "rbac.authorization.k8s.io", "version": "v1", "resource": "rolebindings"}, UserInfo: map[string]any{"username": "attacker", "uid": "actor-uid", "groups": []string{"system:authenticated"}}, Object: map[string]any{"metadata": map[string]any{"name": "same-name", "namespace": "wallet"}, "roleRef": map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": role}, "subjects": []any{map[string]any{"kind": "User", "name": "attacker"}}}}
	}
	for _, role := range []string{"cluster-admin", "custom-wallet-signer"} {
		t.Run("unapproved-"+role, func(t *testing.T) {
			response := peer.NewAdmissionWebhookHandler().HandleAdmission(request(role))
			if response == nil || response.Allowed {
				t.Fatal("sensitive binding was allowed without a core decision or complete referenced-role analysis")
			}
		})
	}
	t.Run("local-intent-does-not-authorize-different-context", func(t *testing.T) {
		h := peer.NewAdmissionWebhookHandler()
		h.RegisterIntent(&peer.ApprovedIntent{IntentID: "unverified-local-intent", TenantID: "different-tenant", RequestID: "unverified-request", Operation: "CREATE", TargetResource: "same-name", TargetSubject: "different-user", ApprovedBy: "caller-supplied-name", ExpiresAt: time.Now().Add(time.Minute)})
		response := h.HandleAdmission(request("cluster-admin"))
		if response == nil || response.Allowed {
			t.Fatal("name-only local intent authorized another tenant/actor/namespace/object without core approval")
		}
	})
	t.Run("delete-without-preimage-is-not-proven-reduction", func(t *testing.T) {
		r := request("cluster-admin")
		r.Operation = "DELETE"
		r.Object = nil
		r.OldObject = nil
		response := peer.NewAdmissionWebhookHandler().HandleAdmission(r)
		if response == nil || response.Allowed {
			t.Fatal("missing exact preimage/context defaulted to allow")
		}
	})
}

func TestPeerKubernetesSnapshotConformance(t *testing.T) {
	snapshot, err := peer.NewK8sAdapter("tenant-k8s-demo", "k8s-source").FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	wire := new(v1.GraphSnapshot)
	if err := protojson.Unmarshal(raw, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := conformance.Snapshot(wire); err != nil {
		t.Fatal(err)
	}
}
