package workflow

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

type nativePlanJSON KubernetesPlan

func (p KubernetesPlan) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(nativePlanJSON(p))
	if err != nil {
		return nil, err
	}
	if p.legacyEncoding || len(raw) <= 512<<10 {
		return raw, nil
	}
	compact, err := eventstore.EncodePublicGraphBundle([]graph.Data{p.Current, p.Before, p.After})
	if err != nil {
		return nil, err
	}
	p.Current, p.Before, p.After = graph.Data{}, graph.Data{}, graph.Data{}
	return json.Marshal(struct {
		nativePlanJSON
		Projections []byte `json:"projection_bundle"`
	}{nativePlanJSON(p), compact})
}

func (p *KubernetesPlan) UnmarshalJSON(raw []byte) error {
	var wire struct {
		nativePlanJSON
		Projections []byte `json:"projection_bundle"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&wire); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return eventstore.ErrIntegrity
	}
	*p = KubernetesPlan(wire.nativePlanJSON)
	if wire.Projections == nil {
		p.legacyEncoding = true
		return nil
	}
	for _, data := range []graph.Data{p.Current, p.Before, p.After} {
		if len(data.Nodes) > 0 || len(data.Edges) > 0 || len(data.Kubernetes) > 0 || len(data.KubernetesDigests) > 0 {
			return eventstore.ErrIntegrity
		}
	}
	views, err := eventstore.DecodePublicGraphBundle(wire.Projections)
	if err != nil {
		return err
	}
	if len(views) != 3 {
		return eventstore.ErrIntegrity
	}
	p.Current, p.Before, p.After = views[0], views[1], views[2]
	return nil
}
