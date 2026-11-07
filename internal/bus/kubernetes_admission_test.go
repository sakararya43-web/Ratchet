package bus_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

func TestNativeAdmissionSignatureBindsEveryExecutionDimension(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	object := kube.Object{Kind: "RoleBinding", Name: "same-name", Namespace: "finance", RoleKind: "ClusterRole", RoleName: "reader", Subjects: []kube.Subject{{Kind: "User", Name: "alice"}}}
	message := bus.SignedKubernetesAdmission{SchemaVersion: 1, IssuedAt: now, ExpiresAt: now.Add(10 * time.Second), Admission: kube.Admission{Tenant: "tenant", AdmissionUID: "api-server-uid", User: kube.UserInfo{Username: "alice", Groups: []string{"system:authenticated"}}, APIGroup: kube.RBACGroup, APIVersion: "v1", Kind: object.Kind, Resource: "rolebindings", Namespace: object.Namespace, Name: object.Name, SourceResourceVersion: "opaque/source-cut", ApprovedRequestID: uuid.NewString(), CommandID: uuid.NewString(), Mutation: kube.Mutation{Cluster: "cluster", Connector: "source", Operation: "CREATE", After: &object, ObjectDigest: ports.Digest{1}}}}
	digest, err := bus.KubernetesAdmissionSigningDigest(canon.New(), message)
	if err != nil {
		t.Fatal(err)
	}
	message.Signature = ed25519.Sign(private, digest[:])
	pin := bus.KubernetesConnectorKey{Tenant: "tenant", Connector: "source", Cluster: "cluster", PublicKey: pub}
	verified, err := bus.VerifyKubernetesAdmission(canon.New(), pin, message, now)
	if err != nil {
		t.Fatal(err)
	}
	verified.Mutation.After.Subjects[0].Name = "changed"
	if message.Admission.Mutation.After.Subjects[0].Name != "alice" {
		t.Fatal("verified evidence aliases untrusted input")
	}
	clone := func() bus.SignedKubernetesAdmission {
		raw, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		var out bus.SignedKubernetesAdmission
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		edit func(*bus.SignedKubernetesAdmission)
	}{
		{"tenant", func(m *bus.SignedKubernetesAdmission) { m.Admission.Tenant = "other" }},
		{"connector", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.Connector = "other" }},
		{"cluster", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.Cluster = "other" }},
		{"admission uid", func(m *bus.SignedKubernetesAdmission) { m.Admission.AdmissionUID = "other" }},
		{"username", func(m *bus.SignedKubernetesAdmission) { m.Admission.User.Username = "other" }},
		{"user uid", func(m *bus.SignedKubernetesAdmission) { m.Admission.User.UID = "other" }},
		{"groups", func(m *bus.SignedKubernetesAdmission) {
			m.Admission.User.Groups = append(m.Admission.User.Groups, "system:masters")
		}},
		{"extra", func(m *bus.SignedKubernetesAdmission) {
			m.Admission.User.Extra = map[string][]string{"claim": {"admin"}}
		}},
		{"namespace", func(m *bus.SignedKubernetesAdmission) { m.Admission.Namespace = "wallet" }},
		{"roleRef", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.After.RoleName = "cluster-admin" }},
		{"subject", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.After.Subjects[0].Name = "mallory" }},
		{"object digest", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.ObjectDigest = ports.Digest{2} }},
		{"old digest", func(m *bus.SignedKubernetesAdmission) { m.Admission.Mutation.OldObjectDigest = ports.Digest{2} }},
		{"dry run", func(m *bus.SignedKubernetesAdmission) { m.Admission.DryRun = true }},
		{"source cut", func(m *bus.SignedKubernetesAdmission) { m.Admission.SourceResourceVersion = "older" }},
		{"graph floor", func(m *bus.SignedKubernetesAdmission) { m.Admission.MinGraphVersion = 12 }},
		{"request", func(m *bus.SignedKubernetesAdmission) { m.Admission.ApprovedRequestID = uuid.NewString() }},
		{"command", func(m *bus.SignedKubernetesAdmission) { m.Admission.CommandID = uuid.NewString() }},
		{"expiry", func(m *bus.SignedKubernetesAdmission) { m.ExpiresAt = m.ExpiresAt.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := clone()
			tc.edit(&m)
			if _, err := bus.VerifyKubernetesAdmission(canon.New(), pin, m, now); err == nil {
				t.Fatal("tampered admission verified")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), message.ExpiresAt, now.Add(time.Minute)} {
		if _, err := bus.VerifyKubernetesAdmission(canon.New(), pin, message, at); err == nil {
			t.Fatal("out-of-window evidence verified")
		}
	}
	wrong := pin
	wrong.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := bus.VerifyKubernetesAdmission(canon.New(), wrong, message, now); err == nil {
		t.Fatal("wrong pinned key accepted")
	}
	m := clone()
	m.ExpiresAt = now.Add(time.Minute)
	d, err := bus.KubernetesAdmissionSigningDigest(canon.New(), m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = ed25519.Sign(private, d[:])
	if _, err := bus.VerifyKubernetesAdmission(canon.New(), pin, m, now); err == nil {
		t.Fatal("overlong signed admission lifetime accepted")
	}
}
