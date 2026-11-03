package k8s_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

func TestEscalationPrimitivesDetection(t *testing.T) {
	rules := []k8s.PolicyRule{
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"roles", "clusterroles"},
			Verbs:     []string{"bind"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"roles"},
			Verbs:     []string{"escalate"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"users", "serviceaccounts"},
			Verbs:     []string{"impersonate"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{"*"},
			Resources: []string{"*"},
			Verbs:     []string{"*"},
		},
	}

	findings := k8s.DetectEscalationPrimitives(rules)
	if len(findings) < 5 {
		t.Fatalf("expected at least 5 escalation findings, got %d", len(findings))
	}

	foundPrimitives := make(map[string]bool)
	for _, f := range findings {
		foundPrimitives[f.Primitive] = true
	}

	expected := []string{"bind", "escalate", "impersonate", "serviceaccount-token-creation", "cluster-admin-wildcard"}
	for _, exp := range expected {
		if !foundPrimitives[exp] {
			t.Errorf("missing expected escalation finding: %q", exp)
		}
	}
}

func TestAdmissionWebhook_ReductionAlwaysPermitted(t *testing.T) {
	handler := k8s.NewAdmissionWebhookHandler()

	req := &k8s.AdmissionRequest{
		UID:       "uid-delete-001",
		Kind:      map[string]string{"kind": "RoleBinding"},
		Operation: "DELETE",
		Object:    map[string]any{"metadata": map[string]any{"name": "admin-binding"}},
	}

	resp := handler.HandleAdmission(req)
	if !resp.Allowed {
		t.Fatalf("expected reduction (DELETE) to be allowed, got denied: %s", resp.Status.Message)
	}
	if resp.Status.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", resp.Status.Code)
	}
}

func TestAdmissionWebhook_UnapprovedPrivilegeEscalationRefused(t *testing.T) {
	handler := k8s.NewAdmissionWebhookHandler()

	// Role containing "escalate" and "impersonate" without approved intent
	escalatingRole := map[string]any{
		"metadata": map[string]any{"name": "shadow-admin-role"},
		"rules": []map[string]any{
			{
				"apiGroups": []string{""},
				"resources": []string{"serviceaccounts"},
				"verbs":     []string{"impersonate"},
			},
		},
	}

	req := &k8s.AdmissionRequest{
		UID:       "uid-create-escalate-001",
		Kind:      map[string]string{"kind": "Role"},
		Operation: "CREATE",
		Object:    escalatingRole,
	}

	resp := handler.HandleAdmission(req)
	if resp.Allowed {
		t.Fatalf("VIOLATION: unapproved privilege escalation was admitted!")
	}
	if resp.Status.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden, got %d", resp.Status.Code)
	}
}

func TestAdmissionWebhook_ApprovedEscalationAdmittedAndOneTimeConsumed(t *testing.T) {
	handler := k8s.NewAdmissionWebhookHandler()

	// Register one-time approved intent from RATCHET
	intent := &k8s.ApprovedIntent{
		IntentID:       "intent-k8s-approved-101",
		TenantID:       "tenant-k8s-demo",
		RequestID:      "req-approved-01",
		Operation:      "CREATE",
		TargetResource: "emergency-triage-role",
		ApprovedBy:     "user:sec-lead-1",
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		Consumed:       false,
	}
	handler.RegisterIntent(intent)

	roleObj := map[string]any{
		"metadata": map[string]any{"name": "emergency-triage-role"},
		"rules": []map[string]any{
			{
				"apiGroups": []string{"rbac.authorization.k8s.io"},
				"resources": []string{"roles"},
				"verbs":     []string{"escalate"},
			},
		},
	}

	req := &k8s.AdmissionRequest{
		UID:       "uid-approved-001",
		Kind:      map[string]string{"kind": "Role"},
		Operation: "CREATE",
		Object:    roleObj,
	}

	// First admission with approved intent MUST succeed
	resp1 := handler.HandleAdmission(req)
	if !resp1.Allowed {
		t.Fatalf("expected approved escalation to be admitted, got denied: %s", resp1.Status.Message)
	}

	// Second admission with consumed intent MUST fail (one-time use enforced)
	req2 := &k8s.AdmissionRequest{
		UID:       "uid-approved-002-replay",
		Kind:      map[string]string{"kind": "Role"},
		Operation: "CREATE",
		Object:    roleObj,
	}
	resp2 := handler.HandleAdmission(req2)
	if resp2.Allowed {
		t.Fatalf("VIOLATION: replayed admission was permitted with consumed intent!")
	}
}

func TestAdmissionWebhook_ClusterAdminRoleBinding(t *testing.T) {
	handler := k8s.NewAdmissionWebhookHandler()

	bindingObj := map[string]any{
		"metadata": map[string]any{"name": "rogue-cluster-admin-binding"},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     "cluster-admin",
		},
	}

	req := &k8s.AdmissionRequest{
		UID:       "uid-cluster-admin-001",
		Kind:      map[string]string{"kind": "ClusterRoleBinding"},
		Operation: "CREATE",
		Object:    bindingObj,
	}

	// Refused without intent
	resp := handler.HandleAdmission(req)
	if resp.Allowed {
		t.Fatalf("VIOLATION: cluster-admin rolebinding admitted without RATCHET quorum approval!")
	}

	// Register approved intent
	intent := &k8s.ApprovedIntent{
		IntentID:       "intent-cluster-admin-approved",
		TenantID:       "tenant-k8s-demo",
		Operation:      "CREATE",
		TargetResource: "rogue-cluster-admin-binding",
		ApprovedBy:     "user:sec-lead-2",
		ExpiresAt:      time.Now().Add(5 * time.Minute),
		Consumed:       false,
	}
	handler.RegisterIntent(intent)

	// Admitted with valid intent
	respApproved := handler.HandleAdmission(req)
	if !respApproved.Allowed {
		t.Fatalf("expected approved cluster-admin binding to be admitted: %s", respApproved.Status.Message)
	}
}
