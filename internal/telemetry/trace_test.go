package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

func TestSpanLinksAcrossDurableBoundaryWithoutPayloadOrErrorLeakage(t *testing.T) {
	var out bytes.Buffer
	r := telemetry.New(slog.New(slog.NewJSONHandler(&out, nil)))
	corr := uuid.NewString()
	ctx, root := r.Start(context.Background(), "submit", "tenant", corr)
	parent := telemetry.Parent(ctx)
	next := telemetry.Resume(context.Background(), parent, "tenant", corr)
	_, child := r.Start(next, "verification", "tenant", corr)
	child.End(errors.New("SECRET assertion private user@example.com"))
	root.End(nil)
	root.End(nil)
	text := out.String()
	if strings.Contains(text, "SECRET") || strings.Contains(text, "user@example.com") || !strings.Contains(text, `"parent_span_id":"`+strings.Split(parent, "-")[2]+`"`) {
		t.Fatal("trace leakage or broken parent", text)
	}
	counts := r.Counts("tenant")
	if counts["submit"].Spans != 1 || counts["verification"].Errors != 1 || len(r.Counts("other")) != 0 {
		t.Fatal("incorrect or cross-tenant counters", counts)
	}
	wrong := telemetry.Resume(context.Background(), parent, "other", corr)
	if telemetry.Parent(wrong) != "" {
		t.Fatal("cross-tenant trace accepted")
	}
}
