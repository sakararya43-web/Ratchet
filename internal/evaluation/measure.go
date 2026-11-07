package evaluation

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

type Latency struct {
	Name         string  `json:"name"`
	Samples      int     `json:"samples"`
	Warmups      int     `json:"warmups"`
	P50MS        float64 `json:"p50_ms"`
	P95MS        float64 `json:"p95_ms"`
	P99MS        float64 `json:"p99_ms"`
	MaxMS        float64 `json:"max_ms"`
	MeanMS       float64 `json:"mean_ms"`
	TargetMS     float64 `json:"target_ms"`
	WithinTarget bool    `json:"within_target"`
}

func Measure(ctx context.Context, name string, samples, warmups int, targetMS float64, fn func(context.Context) error) (Latency, error) {
	out := Latency{Name: name, Samples: samples, Warmups: warmups, TargetMS: targetMS}
	if samples < 1 || warmups < 0 || targetMS <= 0 || fn == nil {
		return out, errors.New("invalid measurement")
	}
	values := make([]float64, 0, samples)
	for i := -warmups; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		start := time.Now()
		if err := fn(ctx); err != nil {
			return out, err
		}
		elapsed := float64(time.Since(start)) / float64(time.Millisecond)
		if i >= 0 {
			values = append(values, elapsed)
			out.MeanMS += elapsed
		}
	}
	slices.Sort(values)
	percentile := func(p float64) float64 { return values[int(math.Ceil(p*float64(samples)))-1] }
	out.P50MS, out.P95MS, out.P99MS, out.MaxMS = percentile(.50), percentile(.95), percentile(.99), values[samples-1]
	out.MeanMS /= float64(samples)
	out.WithinTarget = out.P99MS < targetMS
	return out, nil
}

type Composition struct {
	Nodes     int            `json:"nodes"`
	Edges     int            `json:"edges"`
	Types     map[string]int `json:"node_types"`
	Relations map[string]int `json:"edge_kinds"`
}

func Describe(data graph.Data) Composition {
	r := Composition{Nodes: len(data.Nodes), Edges: len(data.Edges), Types: map[string]int{}, Relations: map[string]int{}}
	for _, n := range data.Nodes {
		r.Types[n.Type]++
	}
	for _, e := range data.Edges {
		r.Relations[e.Kind]++
	}
	return r
}

type BenignCase struct {
	ID              string        `json:"case_id"`
	Intent          domain.Intent `json:"intent"`
	ExpectedOutcome string        `json:"expected_outcome"`
	ExpectedQuorum  int           `json:"expected_quorum"`
}
type BenignResult struct {
	Scope             string         `json:"scope"`
	Denominator       int            `json:"denominator"`
	Unexpected        int            `json:"unexpected"`
	UnexpectedPercent float64        `json:"unexpected_percent"`
	Outcomes          map[string]int `json:"outcomes"`
	Causes            map[string]int `json:"causes"`
}

// Replay compares against declared legitimate outcomes. Expected independent
// review is not counted as an unexpected hold; execution success is never inferred.
func Replay(ctx context.Context, cases []BenignCase, assess func(context.Context, BenignCase) (domain.Decision, error)) (BenignResult, error) {
	r := BenignResult{Scope: "core submit and assessment; excludes approval ceremony, target execution and user waiting time", Denominator: len(cases), Outcomes: map[string]int{}, Causes: map[string]int{}}
	if len(cases) == 0 || assess == nil {
		return r, errors.New("nonempty declared workload required")
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.ID == "" || seen[c.ID] || c.ExpectedOutcome == "" || c.ExpectedQuorum < 0 {
			return r, errors.New("invalid or duplicate benign case")
		}
		seen[c.ID] = true
		if err := ctx.Err(); err != nil {
			return r, err
		}
		actual, err := assess(ctx, c)
		cause := ""
		if err != nil {
			cause = "assessment error"
			r.Outcomes["ERROR"]++
		} else {
			r.Outcomes[actual.Outcome]++
			if actual.Outcome != c.ExpectedOutcome {
				cause = "unexpected " + actual.Outcome
			} else if actual.Quorum != c.ExpectedQuorum {
				cause = "unexpected quorum"
			}
		}
		if cause != "" {
			r.Unexpected++
			r.Causes[cause]++
		}
	}
	r.UnexpectedPercent = 100 * float64(r.Unexpected) / float64(r.Denominator)
	return r, nil
}
