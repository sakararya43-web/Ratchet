//go:build peerintegration

package conformance_test

import (
	"testing"
	"time"

	peer "github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

// These assertions cover the real peer interface adopted on main under the
// user's connector-fix authorization. Live target tests have kindintegration.
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
		if err := h.RegisterIntent(&peer.ApprovedIntent{IntentID: "unverified-local-intent", TenantID: "different-tenant", RequestID: "unverified-request", Operation: "CREATE", TargetResource: "same-name", TargetSubject: "different-user", ApprovedBy: "caller-supplied-name", ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
			t.Fatal("unauthenticated local intent registration accepted")
		}
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
