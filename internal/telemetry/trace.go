// Package telemetry emits bounded structured spans without accepting arbitrary
// attributes, error messages, payloads or personal identifiers.
package telemetry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Recorder struct {
	logger *slog.Logger
	mu     sync.Mutex
	counts map[string]map[string]Count
}
type Count struct {
	Spans      int64   `json:"spans"`
	Errors     int64   `json:"errors"`
	DurationMS float64 `json:"duration_ms"`
}
type traceContext struct{ trace, span, correlation string }
type contextKey struct{}
type Span struct {
	recorder             *Recorder
	tenant, name, parent string
	trace                traceContext
	start                time.Time
	once                 sync.Once
}

func New(logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Recorder{logger: logger, counts: map[string]map[string]Count{}}
}
func TenantReference(tenant string) string {
	d := sha256.Sum256([]byte("ratchet-telemetry-tenant:" + tenant))
	return hex.EncodeToString(d[:8])
}
func traceID(tenant, correlation string) string {
	d := sha256.Sum256([]byte("ratchet-trace-v1:" + tenant + ":" + correlation))
	return hex.EncodeToString(d[:16])
}
func (r *Recorder) Start(ctx context.Context, name, tenant, correlation string) (context.Context, *Span) {
	if r == nil {
		return ctx, nil
	}
	id, err := uuid.Parse(correlation)
	if err != nil || id == uuid.Nil {
		id = uuid.New()
	}
	c := traceContext{trace: traceID(tenant, id.String()), correlation: id.String()}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		copy(random[:], id[:8])
	}
	c.span = hex.EncodeToString(random[:])
	parent := ""
	if previous, ok := ctx.Value(contextKey{}).(traceContext); ok && previous.trace == c.trace {
		parent = previous.span
	}
	s := &Span{recorder: r, tenant: TenantReference(tenant), name: name, parent: parent, trace: c, start: time.Now()}
	return context.WithValue(ctx, contextKey{}, c), s
}
func Parent(ctx context.Context) string {
	if c, ok := ctx.Value(contextKey{}).(traceContext); ok {
		return "00-" + c.trace + "-" + c.span + "-01"
	}
	return ""
}
func Resume(ctx context.Context, parent, tenant, correlation string) context.Context {
	p := strings.Split(parent, "-")
	if len(p) != 4 || p[0] != "00" || len(p[1]) != 32 || len(p[2]) != 16 || p[3] != "01" || p[1] != traceID(tenant, correlation) {
		return ctx
	}
	if _, err := hex.DecodeString(p[2]); err != nil || p[2] == strings.Repeat("0", 16) {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, traceContext{trace: p[1], span: p[2], correlation: correlation})
}
func (s *Span) End(err error) {
	if s == nil {
		return
	}
	s.once.Do(func() {
		duration := float64(time.Since(s.start)) / float64(time.Millisecond)
		s.recorder.mu.Lock()
		if s.recorder.counts[s.tenant] == nil {
			s.recorder.counts[s.tenant] = map[string]Count{}
		}
		count := s.recorder.counts[s.tenant][s.name]
		count.Spans++
		count.DurationMS += duration
		if err != nil {
			count.Errors++
		}
		s.recorder.counts[s.tenant][s.name] = count
		s.recorder.mu.Unlock()
		s.recorder.logger.Info("core_span", "operation", s.name, "trace_id", s.trace.trace, "span_id", s.trace.span, "parent_span_id", s.parent, "correlation_id", s.trace.correlation, "tenant_ref", s.tenant, "duration_ms", duration, "failed", err != nil)
	})
}
func (r *Recorder) Counts(tenant string) map[string]Count {
	result := map[string]Count{}
	if r == nil {
		return result
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, count := range r.counts[TenantReference(tenant)] {
		result[name] = count
	}
	return result
}

// TransportContext extracts only known opaque correlation/parent fields. The
// transport never logs any part of a connector or ledger payload.
func TransportContext(raw []byte, fallback string) (string, string) {
	var data struct {
		Correlation string `json:"correlation_id"`
		Parent      string `json:"traceparent"`
		Payload     struct {
			Facts struct {
				Correlation string `json:"correlation_id"`
				Change      struct {
					Correlation string `json:"correlation_id"`
				} `json:"change"`
				Input struct {
					Admission string `json:"admission_id"`
				} `json:"input"`
			} `json:"facts"`
		} `json:"payload"`
	}
	if len(raw) <= 1<<20 && json.Unmarshal(raw, &data) == nil {
		for _, value := range []string{data.Correlation, data.Payload.Facts.Correlation, data.Payload.Facts.Change.Correlation, data.Payload.Facts.Input.Admission} {
			if id, err := uuid.Parse(value); err == nil && id != uuid.Nil {
				return id.String(), data.Parent
			}
		}
	}
	return fallback, ""
}
