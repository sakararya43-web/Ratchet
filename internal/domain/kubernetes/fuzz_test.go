package kubernetes_test

import (
	"encoding/json"
	"testing"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

func FuzzNormalizedStateAndMutation(f *testing.F) {
	f.Add([]byte(`{"cluster_id":"cluster","resource_version":"rv","complete":true}`), []byte(`{}`))
	f.Add([]byte(`null`), []byte(`{"operation":"DELETE"}`))
	f.Fuzz(func(t *testing.T, raw, change []byte) {
		if len(raw)+len(change) > 1<<20 {
			t.Skip()
		}
		var s kube.State
		var m kube.Mutation
		if json.Unmarshal(raw, &s) != nil || json.Unmarshal(change, &m) != nil {
			return
		}
		if s.ValidateObserved() != nil || m.Validate() != nil {
			return
		}
		_, _ = s.After(m)
	})
}
