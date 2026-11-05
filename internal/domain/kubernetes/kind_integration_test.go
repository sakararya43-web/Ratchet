//go:build kindintegration

package kubernetes_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

// These tests compare the core semantic matcher with the real API server's RBAC
// authorizer. They do not stand in for the peer adapter/webhook acceptance gate.
func TestKubernetesRulesAgainstActualKindAuthorizer(t *testing.T) {
	config := os.Getenv("RATCHET_KIND_KUBECONFIG")
	if !filepath.IsAbs(config) {
		t.Fatal("explicit absolute RATCHET_KIND_KUBECONFIG required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := func(ctx context.Context, input any, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", config, "--context", "kind-ratchet-phase6"}, args...)...)
		if input != nil {
			raw, err := json.Marshal(input)
			if err != nil {
				return nil, err
			}
			cmd.Stdin = bytes.NewReader(raw)
		}
		return cmd.CombinedOutput()
	}
	create := func(t *testing.T, value any) {
		t.Helper()
		if raw, err := command(ctx, value, "create", "-f", "-"); err != nil {
			t.Fatalf("real cluster create: %v: %s", err, raw)
		}
	}
	prefix := "ratchet-p6-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	namespace, other := prefix, prefix+"-other"
	for _, name := range []string{namespace, other} {
		create(t, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]string{"name": name}})
	}
	clusterRoles, clusterBindings := []string{}, []string{}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, name := range clusterBindings {
			if raw, err := command(cleanup, nil, "delete", "clusterrolebinding", name, "--ignore-not-found=true"); err != nil {
				t.Errorf("cleanup owned binding: %v %s", err, raw)
			}
		}
		for _, name := range clusterRoles {
			if raw, err := command(cleanup, nil, "delete", "clusterrole", name, "--ignore-not-found=true"); err != nil {
				t.Errorf("cleanup owned role: %v %s", err, raw)
			}
		}
		for _, name := range []string{namespace, other} {
			if raw, err := command(cleanup, nil, "delete", "namespace", name, "--wait=false", "--ignore-not-found=true"); err != nil {
				t.Errorf("cleanup owned namespace: %v %s", err, raw)
			}
		}
	})
	sar := func(user string, p kube.Permission) (bool, error) {
		attributes := map[string]string{"namespace": p.Namespace, "group": p.APIGroup, "resource": p.Resource, "subresource": p.Subresource, "verb": p.Verb, "name": p.Name}
		spec := map[string]any{"user": user, "groups": []string{"system:authenticated"}, "resourceAttributes": attributes}
		if p.NonResourceURL != "" {
			delete(spec, "resourceAttributes")
			spec["nonResourceAttributes"] = map[string]string{"path": p.NonResourceURL, "verb": p.Verb}
		}
		raw, err := command(ctx, map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": spec}, "create", "--raw", "/apis/authorization.k8s.io/v1/subjectaccessreviews", "-f", "-")
		if err != nil {
			return false, fmt.Errorf("real SubjectAccessReview: %w: %s", err, raw)
		}
		var result struct {
			Status struct {
				Allowed         bool   `json:"allowed"`
				EvaluationError string `json:"evaluationError"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return false, err
		}
		if result.Status.EvaluationError != "" {
			return false, fmt.Errorf("authorizer evaluation failed: %s", result.Status.EvaluationError)
		}
		return result.Status.Allowed, nil
	}
	cases := []struct {
		name    string
		scope   string
		rule    kube.Rule
		queries []kube.Permission
	}{
		{"namespaced-reader", namespace, kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}, []kube.Permission{{Resource: "pods", Verb: "get", Namespace: namespace}, {Resource: "pods", Verb: "get", Namespace: other}, {Resource: "pods", Subresource: "log", Verb: "get", Namespace: namespace}}},
		{"subresource-pattern", namespace, kube.Rule{APIGroups: []string{"apps"}, Resources: []string{"*/scale"}, Verbs: []string{"update"}}, []kube.Permission{{APIGroup: "apps", Resource: "deployments", Subresource: "scale", Verb: "update", Namespace: namespace}, {APIGroup: "apps", Resource: "deployments", Verb: "update", Namespace: namespace}}},
		{"token-request-name", namespace, kube.Rule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}, ResourceNames: []string{"worker"}}, []kube.Permission{{Resource: "serviceaccounts", Subresource: "token", Verb: "create", Namespace: namespace, Name: "worker"}, {Resource: "serviceaccounts", Subresource: "token", Verb: "create", Namespace: namespace, Name: "other"}}},
		{"top-level-create-name", namespace, kube.Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}, ResourceNames: []string{"report"}}, []kube.Permission{{Resource: "pods", Verb: "create", Namespace: namespace}}},
		{"bind-scoped-clusterrole", namespace, kube.Rule{APIGroups: []string{kube.RBACGroup}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}, ResourceNames: []string{"reader"}}, []kube.Permission{{APIGroup: kube.RBACGroup, Resource: "clusterroles", Verb: "bind", Namespace: namespace, Name: "reader"}, {APIGroup: kube.RBACGroup, Resource: "clusterroles", Verb: "bind", Namespace: other, Name: "reader"}}},
		{"named-escalate", namespace, kube.Rule{APIGroups: []string{kube.RBACGroup}, Resources: []string{"roles"}, Verbs: []string{"escalate"}, ResourceNames: []string{"reader"}}, []kube.Permission{{APIGroup: kube.RBACGroup, Resource: "roles", Verb: "escalate", Namespace: namespace, Name: "reader"}, {APIGroup: kube.RBACGroup, Resource: "roles", Verb: "escalate", Namespace: namespace, Name: "admin"}}},
		{"impersonation", "", kube.Rule{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}, ResourceNames: []string{"alice"}}, []kube.Permission{{Resource: "users", Verb: "impersonate", Name: "alice"}, {Resource: "users", Verb: "impersonate", Name: "bob"}}},
		{"non-resource-prefix", "", kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz/*"}}, []kube.Permission{{Verb: "get", NonResourceURL: "/healthz/ready"}, {Verb: "get", NonResourceURL: "/healthz-admin"}}},
		{"namespaced-non-resource", namespace, kube.Rule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz/*"}}, []kube.Permission{{Verb: "get", NonResourceURL: "/healthz/ready"}}},
	}
	queries := 0
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := fmt.Sprintf("%s-%d", prefix, i)
			user := name + "-user"
			rule := map[string]any{"verbs": tc.rule.Verbs}
			if len(tc.rule.Resources) > 0 {
				rule["apiGroups"], rule["resources"] = tc.rule.APIGroups, tc.rule.Resources
			}
			if len(tc.rule.ResourceNames) > 0 {
				rule["resourceNames"] = tc.rule.ResourceNames
			}
			if len(tc.rule.NonResourceURLs) > 0 {
				rule["nonResourceURLs"] = tc.rule.NonResourceURLs
			}
			witness := map[string]any{"apiGroups": []string{""}, "resources": []string{"configmaps"}, "verbs": []string{"get"}, "resourceNames": []string{"witness"}}
			create(t, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]string{"name": name}, "rules": []any{rule, witness}})
			clusterRoles = append(clusterRoles, name)
			kind := "RoleBinding"
			metadata := map[string]string{"name": name, "namespace": tc.scope}
			if tc.scope == "" {
				kind = "ClusterRoleBinding"
				delete(metadata, "namespace")
				clusterBindings = append(clusterBindings, name)
			}
			create(t, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": metadata, "roleRef": map[string]string{"apiGroup": kube.RBACGroup, "kind": "ClusterRole", "name": name}, "subjects": []any{map[string]string{"apiGroup": kube.RBACGroup, "kind": "User", "name": user}}})
			deadline := time.Now().Add(5 * time.Second)
			for {
				allowed, err := sar(user, kube.Permission{Resource: "configmaps", Verb: "get", Namespace: namespace, Name: "witness"})
				if err != nil {
					t.Fatal(err)
				}
				if allowed {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("real RBAC watch did not observe binding")
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, p := range tc.queries {
				want, err := (kube.ScopedRule{Namespace: tc.scope, Rule: tc.rule}).Allows(p)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := sar(user, p)
				if err != nil || actual != want {
					t.Fatalf("core=%v cluster=%v query=%+v err=%v", want, actual, p, err)
				}
				queries++
			}
		})
	}
	t.Logf("matched actual Kubernetes authorizer for %d queries across %d live RBAC configurations", queries, len(cases))
}
