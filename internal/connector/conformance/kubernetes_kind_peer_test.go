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
	peer "github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

func TestPeerKubernetesAdapterObservesActualKindRole(t *testing.T) {
	config := os.Getenv("RATCHET_KIND_KUBECONFIG")
	if !filepath.IsAbs(config) {
		t.Fatal("explicit absolute RATCHET_KIND_KUBECONFIG required")
	}
	t.Setenv("KUBECONFIG", config)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	snapshot, err := peer.NewK8sAdapter("tenant-k8s-demo", "k8s-source").FetchSnapshot(ctx)
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
