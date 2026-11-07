package kubernetes_test

import (
	"testing"

	"github.com/google/uuid"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func admission(s kube.State) kube.Admission {
	before := s.Objects[0]
	after := before
	after.Rules = []kube.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}
	return kube.Admission{Tenant: "tenant", AdmissionUID: "kubernetes-assigned-uid", User: kube.UserInfo{Username: "alice", Groups: []string{"system:authenticated", "finance-readers"}}, APIGroup: kube.RBACGroup, APIVersion: "v1", Kind: "ClusterRole", Resource: "clusterroles", Name: before.Name, SourceResourceVersion: s.ResourceVersion, MinGraphVersion: 44, ApprovedRequestID: uuid.NewString(), CommandID: uuid.NewString(), Mutation: kube.Mutation{Cluster: s.Cluster, Connector: "source", Operation: "UPDATE", Before: &before, After: &after, ObjectDigest: ports.Digest{1}, OldObjectDigest: ports.Digest{2}}}
}

func TestNativeAdmissionRequiresExactContextAndObservedIdentity(t *testing.T) {
	s := state()
	a := admission(s)
	p, err := a.PrincipalIn(s)
	if err != nil || p.ID != "alice" {
		t.Fatal("valid native context", err)
	}
	if a.AdmissionUID == a.CommandID {
		t.Fatal("test must use independent admission and command identities")
	}
	p.Groups[0] = "changed"
	if s.Principals[0].Groups[0] != "finance-readers" {
		t.Fatal("principal result aliases observed directory")
	}
	for _, tc := range []struct {
		name string
		edit func(*kube.Admission)
	}{
		{"wrong namespace", func(a *kube.Admission) { a.Namespace = "wallet" }},
		{"wrong kind", func(a *kube.Admission) { a.Kind = "RoleBinding" }},
		{"wrong resource", func(a *kube.Admission) { a.Resource = "roles" }},
		{"wrong name", func(a *kube.Admission) { a.Name = "other" }},
		{"wrong group", func(a *kube.Admission) { a.APIGroup = "apps" }},
		{"unknown version", func(a *kube.Admission) { a.APIVersion = "v2" }},
		{"unsupported subresource", func(a *kube.Admission) { a.Subresource = "status" }},
		{"unknown username", func(a *kube.Admission) { a.User.Username = "mallory" }},
		{"unverified uid", func(a *kube.Admission) { a.User.UID = "invented" }},
		{"injected groups", func(a *kube.Admission) { a.User.Groups = append(a.User.Groups, "system:masters") }},
		{"missing group", func(a *kube.Admission) { a.User.Groups = []string{"system:authenticated"} }},
		{"unmodeled extra", func(a *kube.Admission) { a.User.Extra = map[string][]string{"example.com/claim": {"admin"}} }},
		{"stale source cut", func(a *kube.Admission) { a.SourceResourceVersion = "opaque/list-0" }},
		{"wrong cluster", func(a *kube.Admission) { a.Mutation.Cluster = "another-cluster" }},
		{"stale object", func(a *kube.Admission) {
			before := *a.Mutation.Before
			before.ResourceVersion = "older"
			after := *a.Mutation.After
			after.ResourceVersion = "older"
			a.Mutation.Before = &before
			a.Mutation.After = &after
		}},
		{"half approval correlation", func(a *kube.Admission) { a.CommandID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := admission(s)
			tc.edit(&a)
			if _, err := a.PrincipalIn(s); err == nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
}

func TestServiceAccountAdmissionUsesCanonicalUsernameAndObservedUID(t *testing.T) {
	s := state()
	s.Principals[1].UID = "sa-uid"
	a := admission(s)
	a.User = kube.UserInfo{Username: "system:serviceaccount:wallet:worker", UID: "sa-uid", Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:wallet"}}
	p, err := a.PrincipalIn(s)
	if err != nil || p.ID != "worker" {
		t.Fatal("real SA identity failed", err)
	}
	a.User.UID = "recreated-account-uid"
	if _, err := a.PrincipalIn(s); err == nil {
		t.Fatal("recreated service account reused old observation")
	}
	for _, p := range []kube.Principal{{ID: "anon", Kind: "User", Name: "system:anonymous"}, {ID: "confused-sa", Kind: "User", Name: "system:serviceaccount:wallet:worker"}, {ID: "unauth", Kind: "User", Name: "user", Groups: []string{"system:unauthenticated"}}} {
		s := state()
		s.Principals = append(s.Principals, p)
		if s.Validate() == nil {
			t.Fatal("unsupported authentication identity accepted", p.ID)
		}
	}
}

func TestAdmissionCredentialFingerprintRequiresExactDirectoryPin(t *testing.T) {
	s := state()
	s.Principals[0].CredentialID = "X509SHA256:observed-certificate"
	a := admission(s)
	a.User.Extra = map[string][]string{"authentication.kubernetes.io/credential-id": {s.Principals[0].CredentialID}}
	if _, err := a.PrincipalIn(s); err != nil {
		t.Fatal("exact observed credential refused", err)
	}
	for _, extra := range []map[string][]string{nil, {"authentication.kubernetes.io/credential-id": {"different"}}, {"authentication.kubernetes.io/credential-id": {s.Principals[0].CredentialID}, "unmodeled": {"claim"}}} {
		a.User.Extra = extra
		if _, err := a.PrincipalIn(s); err == nil {
			t.Fatal("missing or mismatched credential accepted")
		}
	}
	s = state()
	s.Principals[1].Dormant = true
	s.Principals[1].UID = ""
	a = admission(s)
	a.User = kube.UserInfo{Username: "system:serviceaccount:wallet:worker", Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:wallet"}}
	if _, err := a.PrincipalIn(s); err == nil {
		t.Fatal("unobserved dormant account admitted")
	}
}
