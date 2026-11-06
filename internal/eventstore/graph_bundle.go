package eventstore

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

type graphBundle struct {
	Version int          `json:"version"`
	Base    []byte       `json:"base"`
	Views   []bundleView `json:"views"`
}

type bundleView struct {
	Delta   graph.Delta       `json:"delta"`
	Digests map[string]string `json:"digests,omitempty"`
}

// EncodePublicGraphBundle stores a common authority projection once and exact
// deltas for its comparison views. Native plans normally share almost all facts;
// repeating three full graphs would exceed the immutable transport bound.
func EncodePublicGraphBundle(views []graph.Data) ([]byte, error) {
	if len(views) < 1 || len(views) > 4 {
		return nil, ErrInvalid
	}
	for _, data := range views {
		if len(data.Kubernetes) > 0 {
			return nil, fmt.Errorf("%w: private state in public graph bundle", ErrInvalid)
		}
	}
	base, err := graph.Build(0, views[0])
	if err != nil {
		return nil, err
	}
	raw, err := encodeCompactGraph(base.Data())
	if err != nil {
		return nil, err
	}
	bundle := graphBundle{Version: 1, Base: raw, Views: make([]bundleView, len(views))}
	for i, data := range views {
		view, err := graph.Build(0, data)
		if err != nil {
			return nil, err
		}
		delta, err := base.Difference(view)
		if err != nil {
			return nil, err
		}
		bundle.Views[i] = bundleView{Delta: delta, Digests: data.KubernetesDigests}
	}
	raw, err = json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxGraphPlain {
		return nil, ErrInvalid
	}
	var output bytes.Buffer
	w := gzip.NewWriter(&output)
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if output.Len() > maxGraphCompressed {
		return nil, fmt.Errorf("%w: native comparison bundle is %d compressed bytes (limit %d)", ErrInvalid, output.Len(), maxGraphCompressed)
	}
	return output.Bytes(), nil
}

func DecodePublicGraphBundle(raw []byte) ([]graph.Data, error) {
	if len(raw) == 0 || len(raw) > maxGraphCompressed {
		return nil, ErrIntegrity
	}
	input := bytes.NewReader(raw)
	r, err := gzip.NewReader(input)
	if err != nil {
		return nil, ErrIntegrity
	}
	r.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(r, maxGraphPlain+1))
	closeErr := r.Close()
	if err != nil || closeErr != nil || len(plain) > maxGraphPlain || input.Len() != 0 {
		return nil, ErrIntegrity
	}
	var bundle graphBundle
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&bundle) != nil || d.Decode(new(any)) != io.EOF || bundle.Version != 1 || len(bundle.Views) < 1 || len(bundle.Views) > 4 {
		return nil, ErrIntegrity
	}
	data, err := decodeCompactGraph(bundle.Base)
	if err != nil || len(data.Kubernetes) > 0 {
		return nil, ErrIntegrity
	}
	base, err := graph.Build(0, data)
	if err != nil {
		return nil, ErrIntegrity
	}
	views := make([]graph.Data, len(bundle.Views))
	for i, view := range bundle.Views {
		snapshot, err := base.Overlay(0, view.Delta)
		if err != nil {
			return nil, ErrIntegrity
		}
		views[i] = snapshot.Data()
		views[i].KubernetesDigests = view.Digests
		if _, err := graph.Build(0, views[i]); err != nil {
			return nil, ErrIntegrity
		}
	}
	return views, nil
}
