package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

// KubernetesSourceKey avoids retaining personal/source names in public facts.
func KubernetesSourceKey(cluster string) string { return KubernetesNodeID(cluster, "source", "") }

// NativeEdgeID is recoverable from anonymous endpoints. Raw Kubernetes names or
// binding UIDs are never needed to replay a retained authority edge.
func NativeEdgeID(edge Edge) string {
	edge.ID = ""
	edge.Properties = nil
	return "k8s:" + EdgeID(edge)
}

func KubernetesStateDigest(state kube.State) (string, error) {
	if err := state.ValidateObserved(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("RATCHET_NORMALIZED_KUBERNETES_STATE_V1\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (s *Snapshot) setKubernetes(data Data) error {
	if len(data.Kubernetes) > 32 || len(data.KubernetesDigests) > 32 {
		return ErrInvalid
	}
	s.kubernetesDigests = maps.Clone(data.KubernetesDigests)
	for key, digest := range data.KubernetesDigests {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest || !idPattern.MatchString(key) {
			return ErrInvalid
		}
	}
	if data.Kubernetes == nil {
		return nil
	}
	s.kubernetes = map[string]kube.State{}
	for key, state := range data.Kubernetes {
		if key != KubernetesSourceKey(state.Cluster) {
			return ErrInvalid
		}
		digest, err := KubernetesStateDigest(state)
		if err != nil || digest != data.KubernetesDigests[key] {
			return ErrInvalid
		}
		cloned, err := state.Clone()
		if err != nil {
			return err
		}
		s.kubernetes[key] = cloned
	}
	return nil
}

// KubernetesState fails closed after privacy-key deletion. Retained graph powers
// still support non-personal replay, but are not enough for exact native writes.
func (s *Snapshot) KubernetesState(cluster string) (kube.State, error) {
	state, ok := s.kubernetes[KubernetesSourceKey(cluster)]
	if !ok {
		return kube.State{}, ErrUnavailable
	}
	return state.Clone()
}

func KubernetesSource(version int64, state kube.State) (*Snapshot, error) {
	digest, err := KubernetesStateDigest(state)
	if err != nil {
		return nil, err
	}
	compiled, err := CompileKubernetes(version, state)
	if err != nil {
		return nil, err
	}
	data := compiled.Data()
	key := KubernetesSourceKey(state.Cluster)
	data.Kubernetes = map[string]kube.State{key: state}
	data.KubernetesDigests = map[string]string{key: digest}
	return Build(version, data)
}
