//go:build peerintegration && kindintegration

package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/connector/conformance"
	peer "github.com/sakararya43-web/Ratchet/internal/connector/k8s"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func configuredPeerAdapter(t *testing.T) *peer.K8sAdapter {
	t.Helper()
	config := os.Getenv("RATCHET_KIND_KUBECONFIG")
	if !filepath.IsAbs(config) {
		t.Fatal("explicit absolute RATCHET_KIND_KUBECONFIG required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", config, "auth", "whoami", "-o", "json").Output()
	if err != nil {
		t.Fatal("actual cluster identity", err)
	}
	var self struct {
		Status struct {
			UserInfo kube.UserInfo `json:"userInfo"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &self); err != nil {
		t.Fatal(err)
	}
	credential := ""
	if values := self.Status.UserInfo.Extra["authentication.kubernetes.io/credential-id"]; len(values) == 1 {
		credential = values[0]
	}
	directory := []kube.Principal{{ID: "actual-cluster-admin", Kind: "User", Name: self.Status.UserInfo.Username, UID: self.Status.UserInfo.UID, Groups: self.Status.UserInfo.Groups, CredentialID: credential}}
	for _, name := range []string{"kube-apiserver-kubelet-client", "system:kube-controller-manager", "system:kube-scheduler", "system:kube-proxy"} {
		raw, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", config, "--as", name, "auth", "whoami", "-o", "json").Output()
		if err != nil {
			t.Fatal("actual configured system identity", err)
		}
		var identity struct {
			Status struct {
				UserInfo kube.UserInfo `json:"userInfo"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			t.Fatal(err)
		}
		directory = append(directory, kube.Principal{ID: "native:" + name, Kind: "User", Name: identity.Status.UserInfo.Username, UID: identity.Status.UserInfo.UID, Groups: identity.Status.UserInfo.Groups})
	}
	directory = append(directory, kube.Principal{ID: "anonymous", Kind: "User", Name: "system:anonymous", Groups: []string{"system:unauthenticated"}})
	adapter, err := peer.NewConfiguredAdapter(peer.AdapterConfig{Tenant: "tenant-k8s-demo", Connector: "k8s-source", Cluster: "phase6-kind", Kubeconfig: config, StateDirectory: t.TempDir(), DirectoryComplete: true, Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestPeerKubernetesSnapshotConformance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	snapshot, err := configuredPeerAdapter(t).FetchSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual native snapshot: nodes=%d edges=%d diagnostic_bytes=%d", len(snapshot.Nodes), len(snapshot.Edges), len(raw))
	wire := new(v1.GraphSnapshot)
	if err := protojson.Unmarshal(raw, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := conformance.Snapshot(wire); err != nil {
		t.Fatal(err)
	}
}

func TestPeerKubernetesAdapterObservesActualKindRole(t *testing.T) {
	config := os.Getenv("RATCHET_KIND_KUBECONFIG")
	if !filepath.IsAbs(config) {
		t.Fatal("explicit absolute RATCHET_KIND_KUBECONFIG required")
	}
	t.Setenv("KUBECONFIG", config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name := "ratchet-p6-peer-" + uuid.NewString()
	command := func(ctx context.Context, input []byte, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", config, "--context", "kind-ratchet-phase6"}, args...)...)
		cmd.Stdin = bytes.NewReader(input)
		return cmd.CombinedOutput()
	}
	raw, err := json.Marshal(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]string{"name": name}, "rules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if output, err := command(ctx, raw, "create", "-f", "-"); err != nil {
		t.Fatalf("actual kind role: %v %s", err, output)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if output, err := command(cleanup, nil, "delete", "clusterrole", name, "--ignore-not-found=true"); err != nil {
			t.Errorf("cleanup owned role: %v %s", err, output)
		}
	})
	snapshot, err := configuredPeerAdapter(t).FetchSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range snapshot.Nodes {
		if node.ID == "clusterrole:"+name {
			return
		}
	}
	t.Fatal("actual peer snapshot did not observe the uniquely named ClusterRole just created in kind")
}
