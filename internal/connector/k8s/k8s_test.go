package k8s_test

import (
	"context"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

// Legacy name-only intents and synthetic adapters were removed in Phase 6.
// Positive native admission/read-back coverage runs against real kind through
// the native runtime and connector conformance profiles, not a fake cluster.
func TestUnconfiguredLegacyAdmissionAlwaysFailsClosed(t *testing.T) {
	handler := k8s.NewAdmissionWebhookHandler()
	if err := handler.RegisterIntent(&k8s.ApprovedIntent{IntentID: "local", TargetSubject: "alice", TargetResource: "cluster-admin"}); err == nil {
		t.Fatal("name-only local intent authorized a native write")
	}
	for _, test := range []struct{ name, operation, kind string }{{"delete-without-live-preimage", "DELETE", "RoleBinding"}, {"unapproved-escalation", "CREATE", "Role"}, {"local-intent-is-not-a-core-permit", "UPDATE", "Role"}, {"cluster-admin-binding", "CREATE", "ClusterRoleBinding"}} {
		t.Run(test.name, func(t *testing.T) {
			response := handler.HandleAdmission(&k8s.AdmissionRequest{UID: test.name, Operation: test.operation, Kind: map[string]string{"kind": test.kind}, UserInfo: map[string]any{"username": "alice"}})
			if response.Allowed || response.Status == nil || response.Status.Code != 503 {
				t.Fatal("missing core dependency did not refuse native write", response)
			}
		})
	}
}
func TestLegacyAdapterCannotSynthesizeClusterOrApplyUnboundRoles(t *testing.T) {
	adapter := k8s.NewK8sAdapter("tenant", "source")
	if snapshot, err := adapter.FetchSnapshot(context.Background()); err == nil || snapshot != nil {
		t.Fatal("unconfigured adapter fabricated a cluster")
	}
	for _, reduction := range []bool{false, true} {
		command := &connector.ExecCommand{Action: "ASSIGN_ROLE", TargetIdentity: "alice", ResourceOrRole: "cluster-admin", IsReduction: reduction}
		if _, err := adapter.Execute(context.Background(), command); err == nil {
			t.Fatal("unbound native write accepted")
		}
		if _, err := adapter.Verify(context.Background(), command); err == nil {
			t.Fatal("unbound read-back fabricated")
		}
	}
}
