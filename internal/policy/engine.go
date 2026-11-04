// Package policy evaluates only verified, prepared Rego bundles.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

var ErrUnavailable = errors.New("verified policy unavailable")
var ErrInvalid = errors.New("invalid verified policy")

type Facts struct {
	SchemaVersion  int           `json:"schema_version"`
	GraphVersion   int64         `json:"graph_version"`
	Actor          string        `json:"actor"`
	Operation      string        `json:"operation"`
	Groups         []string      `json:"actor_groups"`
	Complete       bool          `json:"complete"`
	Tier0Weakening bool          `json:"tier0_weakening"`
	NewTier0       bool          `json:"new_tier0"`
	Reduction      bool          `json:"reduction"`
	Responder      bool          `json:"authorized_responder"`
	Owners         []string      `json:"owners"`
	Intent         domain.Intent `json:"intent"`
	Impact         any           `json:"impact"`
}
type Active struct {
	Hash           ports.Digest
	Version        string
	RegistryEpoch  int64
	RegistryDigest ports.Digest
	TrustProof     []byte
	change, auth   rego.PreparedEvalQuery
	data           map[string]any
}

func (a *Active) Data() map[string]any {
	raw, _ := json.Marshal(a.data)
	var copy map[string]any
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (a *Active) Decision(ctx context.Context, facts Facts) (domain.Decision, error) {
	results, err := a.change.Eval(ctx, rego.EvalInput(facts))
	if err != nil || len(results) != 1 || len(results[0].Expressions) != 1 {
		return domain.Decision{}, ErrInvalid
	}
	raw, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return domain.Decision{}, err
	}
	var decision domain.Decision
	if err = json.Unmarshal(raw, &decision); err != nil {
		return decision, ErrInvalid
	}
	return decision, decision.Validate()
}
func (a *Active) Authorize(ctx context.Context, facts Facts) error {
	results, err := a.auth.Eval(ctx, rego.EvalInput(facts))
	if err != nil || len(results) != 1 || len(results[0].Expressions) != 1 || results[0].Expressions[0].Value != true {
		return ErrUnavailable
	}
	return nil
}

// Prepare requires the actual peer verifier and a pinned genesis. Registry
// rotation must use an independently verified history; unsupported epochs fail
// closed rather than accepting a self-declared replacement registry.
func Prepare(ctx context.Context, store *trust.Store, root ports.Digest, tenant string, raw []byte) (*Active, error) {
	if store == nil || root.IsZero() || tenant == "" || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrUnavailable
	}
	registry, err := RegistryFromStore(store, root, tenant)
	if err != nil {
		return nil, err
	}
	return prepareRegistry(ctx, registry, tenant, raw)
}

func PrepareHistorical(ctx context.Context, proof []byte, root ports.Digest, tenant string, raw []byte) (*Active, error) {
	registry, err := VerifyRegistry(proof, root, tenant)
	if err != nil {
		return nil, err
	}
	return prepareRegistry(ctx, registry, tenant, raw)
}

func prepareRegistry(ctx context.Context, registry *Registry, tenant string, raw []byte) (*Active, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrInvalid
	}
	var bundle trust.PolicyBundle
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.TenantID != tenant || bundle.Epoch != registry.Epoch {
		return nil, ErrInvalid
	}
	if _, err := version(bundle.BundleVersion); err != nil {
		return nil, err
	}
	verified, err := trust.NewBundleVerifier(registry.store).Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: bundle verification refused", ErrInvalid)
	}
	if verified.BundleDigest.IsZero() || len(verified.Modules) == 0 || len(verified.Modules) > 32 {
		return nil, ErrInvalid
	}
	caps := ast.CapabilitiesForThisVersion()
	builtins := caps.Builtins[:0]
	// A positive capability list also excludes builtins whose implementation
	// consults implicit certificate/JWT validation time without being marked
	// nondeterministic. Policy upgrades cannot silently acquire host capabilities.
	pure := map[string]bool{}
	for _, name := range []string{"eq", "equal", "neq", "assign", "gt", "gte", "lt", "lte", "internal.member_2", "internal.member_3", "and", "or", "minus", "plus", "mul", "div", "rem", "abs", "ceil", "floor", "round", "sum", "product", "count", "max", "min", "sort", "all", "any", "concat", "contains", "startswith", "endswith", "lower", "upper", "trim_space", "split", "sprintf", "to_number", "is_number", "is_string", "is_boolean", "is_array", "is_object", "is_set", "is_null", "array.concat", "array.slice", "array.reverse", "object.get", "object.keys", "object.union", "object.remove", "json.marshal", "json.unmarshal"} {
		pure[name] = true
	}
	for _, builtin := range caps.Builtins {
		if pure[builtin.Name] && !builtin.IsNondeterministic() {
			builtins = append(builtins, builtin)
		}
	}
	caps.Builtins = builtins
	caps.AllowNet = []string{}
	prepare := func(query string) (rego.PreparedEvalQuery, error) {
		options := []func(*rego.Rego){rego.Query(query), rego.Capabilities(caps), rego.StrictBuiltinErrors(true), rego.Store(inmem.NewFromObject(verified.Data))}
		for name, module := range verified.Modules {
			options = append(options, rego.Module(name, module))
		}
		return rego.New(options...).PrepareForEval(ctx)
	}
	change, err := prepare("data.ratchet.change.decision")
	if err != nil {
		return nil, fmt.Errorf("%w: deterministic change query cannot compile", ErrInvalid)
	}
	auth, err := prepare("data.ratchet.authz.allow")
	if err != nil {
		return nil, fmt.Errorf("%w: authorization query cannot compile", ErrInvalid)
	}
	candidate := &Active{Hash: verified.BundleDigest, Version: verified.BundleVersion, RegistryEpoch: registry.Epoch, RegistryDigest: registry.Digest, TrustProof: append([]byte(nil), registry.Proof...), change: change, auth: auth, data: verified.Data}
	if _, err := candidate.Decision(ctx, Facts{SchemaVersion: 1}); err != nil {
		return nil, fmt.Errorf("%w: required structured decision query unavailable", ErrInvalid)
	}
	denial, err := candidate.auth.Eval(ctx, rego.EvalInput(Facts{SchemaVersion: 1}))
	if err != nil || len(denial) != 1 || len(denial[0].Expressions) != 1 || denial[0].Expressions[0].Value != false {
		return nil, fmt.Errorf("%w: default-deny authorization query required", ErrInvalid)
	}
	return candidate, nil
}
func version(s string) ([3]uint64, error) {
	var out [3]uint64
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return out, ErrInvalid
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != p {
			return out, ErrInvalid
		}
		out[i] = n
	}
	return out, nil
}
func Newer(candidate, prior string) bool {
	a, ea := version(candidate)
	b, eb := version(prior)
	if ea != nil || eb != nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

type Engine struct {
	mu         sync.RWMutex
	active     map[string]*Active
	registries map[string]registryContext
}
type registryContext struct {
	epoch  int64
	digest ports.Digest
}

func NewEngine() *Engine {
	return &Engine{active: map[string]*Active{}, registries: map[string]registryContext{}}
}
func (e *Engine) PublishRegistry(tenant string, r *Registry) error {
	if tenant == "" || r == nil || r.Epoch < 1 || r.Digest.IsZero() {
		return ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prior := e.registries[tenant]
	if r.Epoch < prior.epoch || (r.Epoch == prior.epoch && prior.digest != r.Digest) {
		return ErrInvalid
	}
	e.registries[tenant] = registryContext{r.Epoch, r.Digest}
	return nil
}
func (e *Engine) Current(tenant string) (*Active, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	a := e.active[tenant]
	if a == nil {
		return nil, ErrUnavailable
	}
	if r, ok := e.registries[tenant]; ok && (r.epoch != a.RegistryEpoch || r.digest != a.RegistryDigest) {
		return nil, ErrUnavailable
	}
	return a, nil
}

// Publish follows the durable activation transaction; never call it before commit.
func (e *Engine) Publish(tenant string, a *Active) error {
	if tenant == "" || a == nil || a.RegistryEpoch < 1 || a.RegistryDigest.IsZero() {
		return ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.registries[tenant]; ok && (r.epoch != a.RegistryEpoch || r.digest != a.RegistryDigest) {
		return ErrUnavailable
	}
	if old := e.active[tenant]; old != nil {
		if old.Hash == a.Hash {
			return nil
		}
		if !Newer(a.Version, old.Version) {
			return ErrInvalid
		}
	}
	e.active[tenant] = a
	return nil
}
