//go:build integration

package workflow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/evaluation"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func evaluationArtifact(t *testing.T, name string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
	if dir := os.Getenv("RATCHET_EVALUATION_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPhase5MeasuredPerformance(t *testing.T) {
	sys := setup(t)
	raw, err := os.ReadFile("../../testdata/orgs/exchange-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	demo, err := evaluation.CompileDemo(raw)
	if err != nil {
		t.Fatal(err)
	}
	replaceGraph(t, sys, demo.Data())
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	intent := domain.Intent{Kind: "ROLE_ASSIGN", Target: "user:rahul", Access: "role:wallet-operator"}
	digest, err := canon.New().Digest(intent)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := evaluation.Measure(sys.ctx, "durable inline core; demo unapproved tier-0 intent; excludes network", 100, 5, 50, func(ctx context.Context) error {
		r, err := s.DecideInline(ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:rahul"}, workflow.InlineInput{Intent: intent, ObjectDigest: digest, AdmissionID: uuid.NewString(), TargetRevision: "11"})
		if err == nil && (r.ExecutionAuthorized || r.Decision.Outcome != "REQUIRE_APPROVAL" || r.Decision.Quorum != 2) {
			return fmt.Errorf("inline policy result %s/%d", r.Decision.Outcome, r.Decision.Quorum)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	largeData := evaluation.LargeGraph()
	large, err := graph.Build(1, largeData)
	if err != nil {
		t.Fatal(err)
	}
	delta, err := large.Draft("ROLE_ASSIGN", "principal:0", "role:777")
	if err != nil {
		t.Fatal(err)
	}
	impact, err := evaluation.Measure(sys.ctx, "ImpactDiff; 100k edges; includes overlay and controlled beneficiary", 50, 3, 100, func(context.Context) error { _, err := large.ImpactDiff(delta); return err })
	if err != nil {
		t.Fatal(err)
	}
	evaluationArtifact(t, "performance", struct {
		At           time.Time              `json:"at"`
		OS           string                 `json:"os"`
		Arch         string                 `json:"arch"`
		Go           string                 `json:"go"`
		LogicalCPUs  int                    `json:"logical_cpus"`
		GOMAXPROCS   int                    `json:"gomaxprocs"`
		Demo         evaluation.Composition `json:"demo"`
		Large        evaluation.Composition `json:"large"`
		Measurements []evaluation.Latency   `json:"measurements"`
	}{time.Now().UTC(), runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), runtime.GOMAXPROCS(0), evaluation.Describe(demo.Data()), evaluation.Describe(largeData), []evaluation.Latency{inline, impact}})
}

func TestPhase5BenignCoreReplay(t *testing.T) {
	sys := setup(t)
	base, err := sys.store.CurrentGraph(sys.ctx, sys.tenant, sys.key)
	if err != nil {
		t.Fatal(err)
	}
	data := base.Data()
	cases := []evaluation.BenignCase{}
	for i := range 100 {
		target := fmt.Sprintf("user:legitimate:%d", i)
		data.Nodes = append(data.Nodes, graph.Node{ID: target, Type: "Human"})
		intent := domain.Intent{Kind: "ROLE_ASSIGN", Target: target, Access: "role:finance"}
		quorum := 1
		if i >= 90 {
			intent.Access = "role:admin"
			quorum = 2
		} else if i >= 80 {
			intent.Emergency = i >= 85
			intent.DurationSeconds = 300
			intent.Resources = []string{"reports"}
			intent.Permissions = []string{"read"}
		}
		cases = append(cases, evaluation.BenignCase{ID: fmt.Sprintf("legitimate-%03d", i), Intent: intent, ExpectedOutcome: "REQUIRE_APPROVAL", ExpectedQuorum: quorum})
	}
	replaceGraph(t, sys, data)
	s, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	r, err := evaluation.Replay(sys.ctx, cases, func(ctx context.Context, c evaluation.BenignCase) (domain.Decision, error) {
		request, err := s.Submit(ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, workflow.Submit{CommandID: uuid.New(), Intent: c.Intent, Justification: "Documented legitimate access reviewed by an independent owner"})
		if err != nil {
			return domain.Decision{}, err
		}
		if err := s.Assess(ctx, workflow.JobArgs{Tenant: sys.tenant, Request: request.ID, Revision: request.Revision, Operation: "assess"}); err != nil {
			return domain.Decision{}, err
		}
		assessed, err := sys.store.ReadChange(ctx, sys.tenant, request.ID)
		return assessed.Decision, err
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluationArtifact(t, "benign-replay", struct {
		Composition evaluation.Composition  `json:"graph"`
		Result      evaluation.BenignResult `json:"result"`
	}{evaluation.Describe(data), r})
	if r.UnexpectedPercent >= 5 {
		t.Fatalf("unexpected core assessment outcomes %d/%d: %v", r.Unexpected, r.Denominator, r.Causes)
	}
}
