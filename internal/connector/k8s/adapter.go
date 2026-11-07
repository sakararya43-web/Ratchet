package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
)

type AdapterConfig struct {
	Tenant, Connector, Cluster, Kubeconfig, Context, StateDirectory string
	Directory                                                       []kube.Principal
	DirectoryComplete                                               bool
}

type K8sAdapter struct {
	mu          sync.Mutex
	inventoryMu sync.Mutex
	config      AdapterConfig
	state       kube.State
	revision    int64
}

// NewK8sAdapter retains the legacy constructor but never creates a fake cluster.
// An explicit configured directory is required for a complete native source.
func NewK8sAdapter(tenant, connectorID string) *K8sAdapter {
	return &K8sAdapter{config: AdapterConfig{Tenant: tenant, Connector: connectorID, Cluster: os.Getenv("RATCHET_KUBERNETES_CLUSTER"), Kubeconfig: os.Getenv("KUBECONFIG")}}
}

func NewConfiguredAdapter(config AdapterConfig) (*K8sAdapter, error) {
	if config.Tenant == "" || config.Connector == "" || config.Cluster == "" || !filepath.IsAbs(config.Kubeconfig) || !filepath.IsAbs(config.StateDirectory) || !config.DirectoryComplete {
		return nil, kube.ErrInvalid
	}
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(config.Directory)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &config.Directory); err != nil {
		return nil, err
	}
	return &K8sAdapter{config: config}, nil
}

func (a *K8sAdapter) Name() string { return "ratchet-k8s-adapter" }

func (a *K8sAdapter) kubectl(ctx context.Context, args ...string) ([]byte, error) {
	if !filepath.IsAbs(a.config.Kubeconfig) {
		return nil, errors.New("explicit absolute Kubernetes kubeconfig required")
	}
	base := []string{"--kubeconfig", a.config.Kubeconfig, "--request-timeout=15s"}
	if a.config.Context != "" {
		base = append(base, "--context", a.config.Context)
	}
	command := exec.CommandContext(ctx, "kubectl", append(base, args...)...)
	output := boundedOutput{limit: 16 << 20}
	command.Stdout = &output
	err := command.Run()
	if err != nil {
		return nil, errors.New("live Kubernetes API request failed")
	}
	return output.Bytes(), nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	if len(raw) > b.limit-b.Len() {
		return 0, kube.ErrUnsupported
	}
	return b.Buffer.Write(raw)
}

func (a *K8sAdapter) list(ctx context.Context, resource string) ([]map[string]any, error) {
	raw, err := a.kubectl(ctx, "get", resource, "--all-namespaces", "-o", "json", "--chunk-size=0")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (a *K8sAdapter) discovery(ctx context.Context) ([]kube.APIResource, error) {
	paths := []string{"/api/v1"}
	raw, err := a.kubectl(ctx, "get", "--raw", "/apis")
	if err != nil {
		return nil, err
	}
	var groups struct {
		Groups []struct {
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, err
	}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			paths = append(paths, "/apis/"+v.GroupVersion)
		}
	}
	resources := map[string]kube.APIResource{}
	for _, path := range paths {
		raw, err := a.kubectl(ctx, "get", "--raw", path)
		if err != nil {
			return nil, err
		}
		var list struct {
			GroupVersion string `json:"groupVersion"`
			Resources    []struct {
				Name       string `json:"name"`
				Namespaced bool   `json:"namespaced"`
			} `json:"resources"`
		}
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		group := ""
		if strings.Contains(list.GroupVersion, "/") {
			group = strings.SplitN(list.GroupVersion, "/", 2)[0]
		}
		for _, r := range list.Resources {
			key := group + "\x00" + r.Name
			item := kube.APIResource{Group: group, Resource: r.Name, Namespaced: r.Namespaced}
			if old, ok := resources[key]; ok && old.Namespaced != item.Namespaced {
				return nil, kube.ErrUnsupported
			}
			resources[key] = item
		}
	}
	out := make([]kube.APIResource, 0, len(resources))
	for _, r := range resources {
		out = append(out, r)
	}
	slices.SortFunc(out, func(x, y kube.APIResource) int {
		return strings.Compare(x.Group+"/"+x.Resource, y.Group+"/"+y.Resource)
	})
	return out, nil
}

func (a *K8sAdapter) inventory(ctx context.Context, resources []kube.APIResource) (kube.State, error) {
	state := kube.State{Cluster: a.config.Cluster, ResourceVersion: "pending", Complete: a.config.DirectoryComplete, Principals: slices.Clone(a.config.Directory), Resources: resources}
	items, err := a.list(ctx, "namespaces,serviceaccounts,roles.rbac.authorization.k8s.io,clusterroles.rbac.authorization.k8s.io,rolebindings.rbac.authorization.k8s.io,clusterrolebindings.rbac.authorization.k8s.io")
	if err != nil {
		return state, err
	}
	for _, item := range items {
		raw, err := json.Marshal(item)
		if err != nil {
			return state, err
		}
		var object apiObject
		if err := json.Unmarshal(raw, &object); err != nil {
			return state, err
		}
		switch object.Kind {
		case "Namespace":
			state.Namespaces = append(state.Namespaces, object.Metadata.Name)
		case "ServiceAccount":
			m := object.Metadata
			state.Principals = append(state.Principals, kube.Principal{ID: "sa:" + m.Namespace + ":" + m.Name, UID: m.UID, Kind: "ServiceAccount", Name: m.Name, Namespace: m.Namespace})
		case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
			o, _, err := NormalizeObject(item)
			if err != nil {
				return state, fmt.Errorf("normalize %s: %w", object.Kind, err)
			}
			state.Objects = append(state.Objects, o)
		default:
			return state, kube.ErrUnsupported
		}
	}
	slices.Sort(state.Namespaces)
	// RBAC bindings may deliberately predate a service account. Retain that
	// dormant subject's latent authority without inventing an observed account UID.
	known := map[string]bool{}
	for _, p := range state.Principals {
		known[kube.PrincipalKey(p.Kind, p.Namespace, p.Name)] = true
	}
	for _, binding := range state.Objects {
		for _, subject := range binding.Subjects {
			key := kube.PrincipalKey(subject.Kind, subject.Namespace, subject.Name)
			if subject.Kind == "ServiceAccount" && !known[key] && slices.Contains(state.Namespaces, subject.Namespace) {
				state.Principals = append(state.Principals, kube.Principal{ID: "sa:" + subject.Namespace + ":" + subject.Name, Kind: "ServiceAccount", Name: subject.Name, Namespace: subject.Namespace, Dormant: true})
				known[key] = true
			}
		}
	}
	slices.SortFunc(state.Principals, func(x, y kube.Principal) int { return strings.Compare(x.ID, y.ID) })
	slices.SortFunc(state.Objects, func(x, y kube.Object) int { return strings.Compare(kube.ObjectKey(x), kube.ObjectKey(y)) })
	digest, err := canon.New().Digest(state)
	if err != nil {
		return state, err
	}
	state.ResourceVersion = "cut:" + digest.String()
	if err := state.ValidateObserved(); err != nil {
		return state, fmt.Errorf("complete normalized inventory (%d namespaces, %d principals, %d resources, %d objects): %w", len(state.Namespaces), len(state.Principals), len(state.Resources), len(state.Objects), err)
	}
	return state, nil
}

// NativeSnapshot reads the actual target twice and refuses changing cuts. No
// seeded objects or caller-supplied graph edges can stand in for this inventory.
func (a *K8sAdapter) NativeSnapshot(ctx context.Context) (kube.State, int64, error) {
	a.inventoryMu.Lock()
	defer a.inventoryMu.Unlock()
	if !a.config.DirectoryComplete || !filepath.IsAbs(a.config.StateDirectory) {
		return kube.State{}, 0, kube.ErrUnsupported
	}
	resources, err := a.discovery(ctx)
	if err != nil {
		return kube.State{}, 0, err
	}
	before, err := a.inventory(ctx, resources)
	if err != nil {
		return kube.State{}, 0, err
	}
	after, err := a.inventory(ctx, resources)
	if err != nil {
		return kube.State{}, 0, err
	}
	if before.ResourceVersion != after.ResourceVersion {
		return kube.State{}, 0, errors.New("native inventory changed during the complete cut")
	}
	var cursor struct {
		Tenant, Connector, Cluster, Hash string
		Revision                         int64
	}
	path := filepath.Join(a.config.StateDirectory, "source-cursor.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(raw, &cursor) != nil || cursor.Tenant != a.config.Tenant || cursor.Connector != a.config.Connector || cursor.Cluster != a.config.Cluster || cursor.Revision < 1 {
			return kube.State{}, 0, errors.New("native cursor integrity failure")
		}
	} else if !os.IsNotExist(err) {
		return kube.State{}, 0, err
	}
	if cursor.Hash != after.ResourceVersion {
		cursor.Tenant, cursor.Connector, cursor.Cluster, cursor.Hash = a.config.Tenant, a.config.Connector, a.config.Cluster, after.ResourceVersion
		cursor.Revision++
		raw, err = json.Marshal(cursor)
		if err != nil {
			return kube.State{}, 0, err
		}
		if err := atomicFile(path, raw); err != nil {
			return kube.State{}, 0, err
		}
	}
	a.mu.Lock()
	a.state, a.revision = after, cursor.Revision
	a.mu.Unlock()
	copy, err := after.Clone()
	return copy, a.revision, err
}

func atomicFile(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ratchet-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func (a *K8sAdapter) FetchSnapshot(ctx context.Context) (*connector.GraphSnapshot, error) {
	state, revision, err := a.NativeSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	view, err := graph.CompileKubernetes(0, state)
	if err != nil {
		return nil, err
	}
	result := &connector.GraphSnapshot{TenantID: a.config.Tenant, ConnectorID: a.config.Connector, SourceRevision: revision, Complete: true, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Nodes: []connector.GraphNode{}, Edges: []connector.GraphEdge{}}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(a.config.Tenant+":"+a.config.Connector+":"+state.ResourceVersion)).String()
	result.Envelope = &v1.ConnectorEnvelope{SchemaVersion: 1, TenantId: a.config.Tenant, ConnectorId: a.config.Connector, MessageId: id, CorrelationId: id, SourceRevision: revision}
	for _, n := range view.Data().Nodes {
		result.Nodes = append(result.Nodes, connector.GraphNode{ID: n.ID, Type: n.Type, Tier: n.Tier, Properties: n.Properties})
	}
	for _, e := range view.Data().Edges {
		properties := map[string]string{"grant_id": e.ID}
		for key, value := range e.Properties {
			properties[key] = value
		}
		result.Edges = append(result.Edges, connector.GraphEdge{Source: e.Source, Target: e.Target, Kind: e.Kind, Action: e.Action, Properties: properties})
	}
	// Preserve diagnostic role IDs used by existing connector clients. Authority
	// ingestion uses the signed normalized state, never these diagnostic aliases.
	for _, o := range state.Objects {
		if o.Kind == "ClusterRole" {
			result.Nodes = append(result.Nodes, connector.GraphNode{ID: "clusterrole:" + o.Name, Type: "Role", Tier: 2})
		}
	}
	return result, nil
}

func (a *K8sAdapter) FetchDelta(context.Context, int64) (*connector.GraphDelta, error) {
	return nil, errors.New("native sources require complete normalized cuts")
}
func (a *K8sAdapter) Execute(context.Context, *connector.ExecCommand) (*connector.ExecResult, error) {
	return nil, errors.New("legacy unbound native writes are forbidden; use staged admission")
}
func (a *K8sAdapter) Verify(context.Context, *connector.ExecCommand) (*connector.ObservedState, error) {
	return nil, errors.New("native read-back requires an exact staged object commitment")
}
