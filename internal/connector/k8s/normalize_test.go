package k8s_test

import (
	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
	"testing"
)

func TestUnverifiedLocalIntentAndMissingPreimageNeverAuthorize(t *testing.T) {
	h := k8s.NewAdmissionWebhookHandler()
	if h.RegisterIntent(&k8s.ApprovedIntent{IntentID: "local-name-only"}) == nil {
		t.Fatal("unverified intent registration accepted")
	}
	for _, op := range []string{"CREATE", "UPDATE", "DELETE"} {
		if response := h.HandleAdmission(&k8s.AdmissionRequest{UID: "uid", Operation: op}); response == nil || response.Allowed {
			t.Fatal("unconfigured native boundary admitted", op)
		}
	}
}

func TestNativeObjectNormalizationRetainsNamesLabelsRuleConstraintsAndRejectsUnmodeledEffects(t *testing.T) {
	raw := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": map[string]any{"name": "scoped", "namespace": "finance", "labels": map[string]any{"aggregation": "true"}}, "rules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get"}, "resourceNames": []string{"literal*"}}}}
	o, digest, err := k8s.NormalizeObject(raw)
	if err != nil || o.Rules[0].ResourceNames[0] != "literal*" || o.Labels["aggregation"] != "true" {
		t.Fatal("native constraint lost", err)
	}
	metadata := raw["metadata"].(map[string]any)
	metadata["creationTimestamp"] = nil
	_, same, err := k8s.NormalizeObject(raw)
	if err != nil || same != digest {
		t.Fatal("API bookkeeping changed submitted authority", err)
	}
	metadata["annotations"] = map[string]string{"controller": "different"}
	_, changed, err := k8s.NormalizeObject(raw)
	if err != nil || changed == digest {
		t.Fatal("raw metadata was not bound", err)
	}
	metadata["finalizers"] = []string{"unexpected/controller"}
	if _, _, err := k8s.NormalizeObject(raw); err == nil {
		t.Fatal("unknown deletion effects treated as safe")
	}
}
