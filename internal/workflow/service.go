// Package workflow coordinates durable changes around the pure domain model.
package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

var ErrPermission = errors.New("operation not authorized")
var ErrDependency = errors.New("verified workflow dependency unavailable")

type Actor struct{ TenantID, ID string }
type Service struct {
	Store      *eventstore.Store
	Policies   *policy.Engine
	key        []byte
	jobs       *river.Client[pgx.Tx]
	approvals  ports.ApprovalVerifier
	executions map[string]*Execution
	tenants    map[string]bool
	config     Config
	observer   *telemetry.Recorder
}
type JobArgs struct {
	Tenant    string `json:"tenant_id"`
	Request   string `json:"request_id"`
	Revision  int64  `json:"revision"`
	Operation string `json:"operation"`
}

func (JobArgs) Kind() string { return "ratchet_change_v1" }

type worker struct {
	river.WorkerDefaults[JobArgs]
	service *Service
}

func (w *worker) Work(ctx context.Context, j *river.Job[JobArgs]) error {
	if !w.service.tenants[j.Args.Tenant] {
		return river.JobCancel(ErrPermission)
	}
	if j.Args.Operation == "assess" {
		return w.service.Assess(ctx, j.Args)
	}
	if j.Args.Operation == "guard" {
		return w.service.Guard(ctx, j.Args)
	}
	if j.Args.Operation == "reconcile" {
		return w.service.Reconcile(ctx, j.Args)
	}
	if j.Args.Operation == "incident" {
		return w.service.ReconcileDriftIncident(ctx, j.Args)
	}
	return river.JobCancel(domain.ErrInvalid)
}
func New(pool *pgxpool.Pool, store *eventstore.Store, policies *policy.Engine, key []byte, approvals ports.ApprovalVerifier, tenants []string, execution ...*Execution) (*Service, error) {
	return NewConfigured(pool, store, policies, key, approvals, tenants, Config{}, execution...)
}

// Config is frozen at construction. Zero selects the documented default.
type Config struct {
	ApprovalLifetime      time.Duration
	Observer              *telemetry.Recorder
	PublishedGraphVersion func(context.Context, string) (int64, error)
	DriftResponders       map[string]string
	CheckpointSchedules   map[string]CheckpointSchedule
}

func NewConfigured(pool *pgxpool.Pool, store *eventstore.Store, policies *policy.Engine, key []byte, approvals ports.ApprovalVerifier, tenants []string, config Config, execution ...*Execution) (*Service, error) {
	if config.ApprovalLifetime == 0 {
		config.ApprovalLifetime = 15 * time.Minute
	}
	if config.ApprovalLifetime < time.Second || config.ApprovalLifetime > 24*time.Hour {
		return nil, domain.ErrInvalid
	}
	if config.Observer == nil {
		config.Observer = telemetry.New(nil)
	}
	config.DriftResponders = maps.Clone(config.DriftResponders)
	config.CheckpointSchedules = maps.Clone(config.CheckpointSchedules)
	if pool == nil || store == nil || policies == nil || len(key) != 32 || len(tenants) == 0 {
		return nil, domain.ErrInvalid
	}
	s := &Service{Store: store, Policies: policies, key: append([]byte(nil), key...), approvals: approvals, executions: map[string]*Execution{}, tenants: map[string]bool{}, config: config}
	s.observer = config.Observer
	queues := map[string]river.QueueConfig{}
	for _, tenant := range tenants {
		if tenant == "" || s.tenants[tenant] {
			return nil, domain.ErrInvalid
		}
		s.tenants[tenant] = true
		queues[tenantQueue(tenant)] = river.QueueConfig{MaxWorkers: 4}
	}
	for _, e := range execution {
		if e == nil || s.executions[e.Tenant] != nil || !s.tenants[e.Tenant] {
			return nil, domain.ErrInvalid
		}
		s.executions[e.Tenant] = e
	}
	for tenant, responder := range config.DriftResponders {
		if !s.tenants[tenant] || responder == "" {
			return nil, domain.ErrInvalid
		}
	}
	for tenant, schedule := range config.CheckpointSchedules {
		if schedule.Interval == 0 {
			schedule.Interval = 15 * time.Minute
		}
		if !s.tenants[tenant] || schedule.Actor == "" || schedule.Interval < time.Second || schedule.Interval > 24*time.Hour {
			return nil, domain.ErrInvalid
		}
		s.config.CheckpointSchedules[tenant] = schedule
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &worker{service: s})
	river.AddWorker(workers, &approvalExpiryWorker{service: s})
	river.AddWorker(workers, &grantExpiryWorker{service: s})
	river.AddWorker(workers, &checkpointTickWorker{service: s})
	river.AddWorker(workers, &checkpointDeliveryWorker{service: s})
	jobs, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: "ratchet_jobs", Workers: workers, Queues: queues})
	if err != nil {
		return nil, err
	}
	s.jobs = jobs
	return s, nil
}
func (s *Service) Start(ctx context.Context) error {
	if err := s.ensureCheckpointSchedules(ctx); err != nil {
		return err
	}
	return s.jobs.Start(ctx)
}
func (s *Service) Ready(ctx context.Context) error {
	if s.approvals == nil || len(s.executions) != len(s.tenants) {
		return ErrDependency
	}
	return s.PolicyReady(ctx)
}
func (s *Service) PolicyReady(ctx context.Context) error {
	for tenant := range s.tenants {
		if err := s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, _ time.Time) error { _, err := s.active(ctx, tx, tenant); return err }); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) Stop(ctx context.Context) error { return s.jobs.Stop(ctx) }
func (s *Service) enqueue(ctx context.Context, tx pgx.Tx, args JobArgs) error {
	if !s.tenants[args.Tenant] {
		return ErrPermission
	}
	_, err := s.jobs.InsertTx(ctx, tx, args, &river.InsertOpts{Queue: tenantQueue(args.Tenant), MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true}})
	return err
}
func (s *Service) scheduleReconciliation(ctx context.Context, tx pgx.Tx, c domain.Change, now time.Time) error {
	_, err := s.jobs.InsertTx(ctx, tx, JobArgs{c.TenantID, c.ID, c.Revision + 1, "reconcile"}, &river.InsertOpts{Queue: tenantQueue(c.TenantID), ScheduledAt: now.Add(20 * time.Second), MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true}})
	return err
}
func tenantQueue(tenant string) string {
	hash := sha256.Sum256([]byte(tenant))
	return "r_" + hex.EncodeToString(hash[:24])
}
func groups(snapshot *graph.Snapshot, actor string) ([]string, error) {
	n, err := snapshot.Node(actor)
	if err != nil || n.Type != "Human" || n.Properties["disabled"] == "true" {
		return nil, ErrPermission
	}
	reach, err := snapshot.Reach(actor)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, n := range reach.Nodes {
		if n.Type == "Group" || n.Type == "Role" {
			out = append(out, n.ID)
		}
	}
	return out, nil
}
func (s *Service) active(ctx context.Context, tx pgx.Tx, tenant string) (*policy.Active, error) {
	a, err := s.Policies.Current(tenant)
	if err != nil {
		return nil, ErrDependency
	}
	var digest []byte
	if err := tx.QueryRow(ctx, `SELECT digest FROM ratchet.policy_artifacts WHERE tenant_id=$1 ORDER BY event_position DESC LIMIT 1`, tenant).Scan(&digest); err != nil {
		return nil, ErrDependency
	}
	if string(digest) != string(a.Hash[:]) {
		return nil, ErrDependency
	}
	var registry []byte
	if err := tx.QueryRow(ctx, `SELECT digest FROM ratchet.registry_artifacts WHERE tenant_id=$1 ORDER BY epoch DESC LIMIT 1`, tenant).Scan(&registry); err != nil || string(registry) != string(a.RegistryDigest[:]) {
		return nil, ErrDependency
	}
	return a, nil
}
func (s *Service) context(ctx context.Context, tx pgx.Tx, actor Actor, operation string, owners []string) (*graph.Snapshot, *policy.Active, error) {
	if !s.tenants[actor.TenantID] {
		return nil, nil, ErrPermission
	}
	snapshot, err := s.Store.GraphWithin(ctx, tx, actor.TenantID, s.key)
	if err != nil {
		return nil, nil, err
	}
	a, err := s.active(ctx, tx, actor.TenantID)
	if err != nil {
		return nil, nil, err
	}
	memberships, err := groups(snapshot, actor.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := a.Authorize(ctx, policy.Facts{Actor: actor.ID, Operation: operation, Groups: memberships, Owners: owners}); err != nil {
		return nil, nil, ErrPermission
	}
	return snapshot, a, nil
}
func (s *Service) Authorize(ctx context.Context, actor Actor, operation string) error {
	return s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error { _, _, err := s.context(ctx, tx, actor, operation, nil); return err })
}

type Submit struct {
	Intent          domain.Intent
	Justification   string
	CommandID       uuid.UUID
	MinGraphVersion int64
	CorrelationID   string
}

func (s *Service) Submit(ctx context.Context, actor Actor, input Submit) (change domain.Change, err error) {
	if err := input.Intent.Validate(); err != nil {
		return domain.Change{}, err
	}
	if input.Intent.IncidentID != "" {
		id, _ := uuid.Parse(input.Intent.IncidentID)
		input.Intent.IncidentID = id.String()
	}
	if len(strings.TrimSpace(input.Justification)) < 10 || len(input.Justification) > 4000 || input.CommandID == uuid.Nil {
		return domain.Change{}, domain.ErrInvalid
	}
	if input.MinGraphVersion < 0 || input.MinGraphVersion > 1<<53-1 {
		return domain.Change{}, domain.ErrInvalid
	}
	if input.CorrelationID == "" {
		input.CorrelationID = input.CommandID.String()
	}
	if id, err := uuid.Parse(input.CorrelationID); err != nil || id == uuid.Nil {
		return domain.Change{}, domain.ErrInvalid
	}
	ctx, span := s.observer.Start(ctx, "submit", actor.TenantID, input.CorrelationID)
	defer func() { span.End(err) }()
	privateDigest, err := canon.New().Digest(struct {
		Context string `json:"context"`
	}{input.Justification})
	if err != nil {
		return domain.Change{}, err
	}
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+input.CommandID.String())).String()
	recordID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(requestID+":"+privateDigest.String()))
	private, err := eventstore.SealPrivate(s.key, actor.TenantID, recordID, "workflow-v1", []byte(input.Justification))
	if err != nil {
		return domain.Change{}, err
	}
	digest, err := canon.New().Digest(struct {
		Actor           Actor
		Intent          domain.Intent
		PrivateDigest   ports.Digest
		MinGraphVersion int64
		CorrelationID   string
	}{actor, input.Intent, privateDigest, input.MinGraphVersion, input.CorrelationID})
	if err != nil {
		return domain.Change{}, err
	}
	mutation := eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: requestID, ID: input.CommandID, InputDigest: digest, Private: &private}
	if input.Intent.IncidentID != "" {
		mutation.Additional = func(tx pgx.Tx, _ eventstore.Receipt) error { return s.recordRestoration(ctx, tx, actor, requestID) }
	}
	return s.Store.MutateChange(ctx, mutation, func(tx pgx.Tx, now time.Time, current domain.Change) ([]domain.Event, error) {
		snapshot, _, err := s.context(ctx, tx, actor, "submit", nil)
		if err != nil {
			return nil, err
		}
		if input.MinGraphVersion < 0 || snapshot.Version() < input.MinGraphVersion {
			return nil, graph.ErrUnavailable
		}
		if input.Intent.IncidentID != "" {
			if err := s.validateRestoration(ctx, tx, actor, input.Intent); err != nil {
				return nil, err
			}
		}
		if _, err := snapshot.Draft(input.Intent.Kind, input.Intent.Target, input.Intent.Access); err != nil && input.Intent.Kind != "MODIFY_SAFEGUARD" {
			return nil, err
		}
		if input.Intent.Kind == "MODIFY_SAFEGUARD" {
			if len(input.Intent.Parameters) > 0 {
				_, err = snapshot.EditSafeguard(input.Intent.Target, input.Intent.Parameters)
			} else {
				_, err = snapshot.Draft(input.Intent.Kind, input.Intent.Target, input.Intent.Access)
			}
			if err != nil {
				return nil, err
			}
		}
		events, err := domain.Decide(current, domain.Command{Kind: "SUBMIT", At: now, Submission: &domain.Change{ID: requestID, CorrelationID: input.CorrelationID, TenantID: actor.TenantID, Requester: actor.ID, Intent: input.Intent, PrivateReference: private.ID.String(), PrivateDigest: privateDigest}})
		if err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, JobArgs{actor.TenantID, requestID, 1, "assess"}); err != nil {
			return nil, err
		}
		return events, nil
	})
}
func impact(snapshot *graph.Snapshot, intent domain.Intent) (graph.Impact, graph.Delta, error) {
	var delta graph.Delta
	var err error
	if intent.Kind == "MODIFY_SAFEGUARD" && len(intent.Parameters) > 0 {
		delta, err = snapshot.EditSafeguard(intent.Target, intent.Parameters)
	} else {
		delta, err = snapshot.Draft(intent.Kind, intent.Target, intent.Access)
	}
	if err != nil {
		return graph.Impact{}, delta, err
	}
	result, err := snapshot.ImpactDiff(delta)
	return result, delta, err
}
func ownersFor(a *policy.Active, result graph.Impact) []string {
	mapping, _ := a.Data()["resource_owners"].(map[string]any)
	resources := map[string]bool{}
	for _, item := range result.Affected {
		for _, n := range item.NewResources {
			resources[n.ID] = true
		}
		for _, p := range item.RemovedPowers {
			resources[p.NodeID] = true
		}
	}
	var common map[string]bool
	for id := range resources {
		values, _ := mapping[id].([]any)
		next := map[string]bool{}
		for _, value := range values {
			if name, ok := value.(string); ok {
				next[name] = true
			}
		}
		if common == nil {
			common = next
		} else {
			for actor := range common {
				if !next[actor] {
					delete(common, actor)
				}
			}
		}
	}
	out := []string{}
	for actor := range common {
		out = append(out, actor)
	}
	slices.Sort(out)
	return out
}
func factsFor(ctx context.Context, snapshot *graph.Snapshot, a *policy.Active, c domain.Change, result graph.Impact) policy.Facts {
	memberships, err := groups(snapshot, c.Requester)
	f := policy.Facts{SchemaVersion: 2, GraphVersion: snapshot.Version(), RegistryEpoch: a.RegistryEpoch, RegistryDigest: a.RegistryDigest.String(), Actor: c.Requester, Operation: "assess", Groups: memberships, Complete: err == nil, Intent: c.Intent, Reduction: result.MonotonicReduction, Owners: ownersFor(a, result), Impact: result, Responder: a.Authorize(ctx, policy.Facts{Actor: c.Requester, Operation: "reduce", Groups: memberships}) == nil}
	for _, n := range result.Weakened {
		if n.Tier == 0 {
			f.Tier0Weakening = true
		}
	}
	for _, i := range result.Affected {
		if len(i.NewRoutes) > 0 {
			f.NewTier0 = true
		}
		for _, p := range i.NewPowers {
			if n, err := snapshot.Node(p.NodeID); err == nil && n.Tier == 0 && (n.Type == "Resource" || n.Type == "Safeguard") {
				f.NewTier0 = true
			}
		}
	}
	f.SchemaVersion = 3
	f.Scope = scopeReview(c.Intent, result)
	return f
}
func hold(c domain.Change, now time.Time, reason string) ([]domain.Event, error) {
	return domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: domain.Decision{Outcome: "HOLD", Reasons: []string{reason}}})
}
func jobID(args JobArgs) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("%s:%s:%d:%s", args.Tenant, args.Request, args.Revision, args.Operation)))
}
func (s *Service) Assess(ctx context.Context, args JobArgs) (err error) {
	var span *telemetry.Span
	defer func() { span.End(err) }()
	digest, err := canon.New().Digest(args)
	if err != nil {
		return err
	}
	_, err = s.Store.MutateChange(ctx, eventstore.ChangeMutation{TenantID: args.Tenant, ActorID: "core-assessor", RequestID: args.Request, ID: jobID(args), ExpectedRevision: args.Revision, InputDigest: digest}, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		ctx, span = s.observer.Start(ctx, "assessment", args.Tenant, c.CorrelationID)
		snapshot, err := s.Store.GraphWithin(ctx, tx, args.Tenant, s.key)
		if err != nil {
			return hold(c, now, "graph unavailable or resync required")
		}
		a, err := s.active(ctx, tx, args.Tenant)
		if err != nil {
			return hold(c, now, "verified policy unavailable")
		}
		result, _, err := impact(snapshot, c.Intent)
		if err != nil {
			return hold(c, now, "impact context cannot be proved")
		}
		facts := factsFor(ctx, snapshot, a, c, result)
		decision, err := s.decidePolicy(ctx, c.TenantID, c.CorrelationID, a, facts)
		if err != nil {
			return hold(c, now, "policy evaluation unavailable")
		}
		envelope := &domain.Envelope{FormatVersion: 2, TenantID: c.TenantID, RequestID: c.ID, Revision: c.Revision + 2, Requester: c.Requester, Intent: c.Intent, GraphVersion: snapshot.Version(), PolicyDigest: a.Hash, RegistryEpoch: a.RegistryEpoch, RegistryDigest: a.RegistryDigest, ExpiresAt: now.Add(s.config.ApprovalLifetime), PrivateReference: c.PrivateReference, PrivateDigest: c.PrivateDigest}
		envelope.ImpactDigest, err = canon.New().Digest(result)
		if err != nil {
			return nil, err
		}
		bound, err := canon.New().Digest(envelope)
		if err != nil {
			return nil, err
		}
		graphDigest, err := canon.New().Digest(snapshot.Data())
		if err != nil {
			return nil, err
		}
		replayFacts, err := json.Marshal(recordedFacts{Evaluator: evaluatorVersion, Input: facts, GraphDigest: graphDigest})
		if err != nil {
			return nil, err
		}
		events, err := domain.Decide(c, domain.Command{Kind: "ASSESS", At: now, Decision: decision, Envelope: envelope, Digest: bound, Facts: replayFacts, Scope: facts.Scope})
		if err != nil {
			return nil, err
		}
		if decision.Outcome == "ALLOW" || decision.Outcome == "REQUIRE_APPROVAL" {
			if err := s.scheduleApprovalExpiry(ctx, tx, c, bound, envelope.ExpiresAt); err != nil {
				return nil, err
			}
		}
		if decision.Outcome == "ALLOW" {
			last := events[len(events)-1].Change
			if err := s.enqueue(ctx, tx, JobArgs{c.TenantID, c.ID, last.Revision, "guard"}); err != nil {
				return nil, err
			}
		}
		return events, nil
	})
	if errors.Is(err, eventstore.ErrVersionConflict) {
		return nil
	}
	return err
}
func eligible(snapshot *graph.Snapshot, c domain.Change, result graph.Impact, delta graph.Delta, actor string, owners []string) error {
	if actor == c.Requester {
		return ErrPermission
	}
	memberships, err := groups(snapshot, actor)
	if err != nil {
		return err
	}
	permitted := false
	for _, group := range c.Decision.Groups {
		if group == "resource-owner" && slices.Contains(owners, actor) {
			permitted = true
		}
		if slices.Contains(memberships, group) {
			permitted = true
		}
	}
	if !permitted {
		return ErrPermission
	}
	after, err := snapshot.Overlay(snapshot.Version(), delta)
	if err != nil {
		return err
	}
	for _, view := range []*graph.Snapshot{snapshot, after} {
		control, err := view.ControlSet(c.Requester)
		if err != nil {
			return err
		}
		if slices.Contains(control, actor) {
			return ErrPermission
		}
	}
	beneficiaries := map[string]bool{actor: true}
	for _, view := range []*graph.Snapshot{snapshot, after} {
		control, err := view.ControlSet(actor)
		if err != nil {
			return err
		}
		for _, id := range control {
			beneficiaries[id] = true
		}
	}
	for _, item := range result.Affected {
		if beneficiaries[item.IdentityID] && (len(item.NewPowers) > 0 || len(item.NewControlled) > 0 || len(item.NewRoutes) > 0 || len(item.Weakened) > 0) {
			return ErrPermission
		}
	}
	return nil
}
func (s *Service) Approve(ctx context.Context, actor Actor, request string, id uuid.UUID, revision int64, expected ports.Digest, submission ports.ApprovalSubmission) (domain.Change, error) {
	if s.approvals == nil {
		return domain.Change{}, ErrDependency
	}
	submission.TenantID = actor.TenantID
	submission.ActorID = actor.ID
	digest, err := canon.New().Digest(struct {
		Actor    Actor
		Request  string
		Revision int64
		Expected ports.Digest
		Proof    ports.ApprovalSubmission
	}{actor, request, revision, expected, submission})
	if err != nil {
		return domain.Change{}, err
	}
	return s.Store.MutateChange(ctx, eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: request, ID: id, ExpectedRevision: revision, InputDigest: digest}, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		snapshot, err := s.Store.GraphWithin(ctx, tx, actor.TenantID, s.key)
		if err != nil {
			return nil, err
		}
		a, err := s.active(ctx, tx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		result, delta, err := impact(snapshot, c.Intent)
		if err != nil {
			return nil, err
		}
		owners := ownersFor(a, result)
		if _, _, err := s.context(ctx, tx, actor, "approve", owners); err != nil {
			return nil, err
		}
		if err := eligible(snapshot, c, result, delta, actor.ID, owners); err != nil {
			return nil, err
		}
		// Even invalid/stale proof must not let an unauthorized caller mutate a
		// request by forcing it into Held before their permissions are checked.
		if c.Envelope == nil || c.Digest != expected || c.Envelope.GraphVersion != snapshot.Version() || c.Envelope.PolicyDigest != a.Hash || c.Envelope.RegistryEpoch != a.RegistryEpoch || c.Envelope.RegistryDigest != a.RegistryDigest {
			return domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
		}
		verified, err := s.approvals.Verify(ctx, submission, c.Digest)
		if err != nil {
			return nil, ErrPermission
		}
		if verified.ActorID != actor.ID || verified.TenantID != actor.TenantID || !verified.UserVerified || verified.ChangeDigest != c.Digest || !slices.Equal(verified.CredentialID, submission.CredentialID) || verified.VerifiedAt.After(now.Add(time.Minute)) || verified.VerifiedAt.Before(now.Add(-time.Minute)) {
			return nil, ErrPermission
		}
		events, err := domain.Decide(c, domain.Command{Kind: "APPROVE", At: now, Approval: &domain.Approval{ActorID: actor.ID, CredentialID: verified.CredentialID, Digest: c.Digest, VerifiedAt: verified.VerifiedAt, Evidence: submission}})
		if err != nil {
			return nil, err
		}
		last := events[len(events)-1].Change
		if last.State == domain.Approved {
			if err := s.enqueue(ctx, tx, JobArgs{c.TenantID, c.ID, last.Revision, "guard"}); err != nil {
				return nil, err
			}
		}
		return events, nil
	})
}
func (s *Service) Review(ctx context.Context, actor Actor, request string, id uuid.UUID, revision int64, kind, reason string) (domain.Change, error) {
	if !slices.Contains([]string{"HOLD", "REJECT", "MORE_INFO"}, kind) || len(strings.TrimSpace(reason)) < 3 || len(reason) > 2000 {
		return domain.Change{}, domain.ErrInvalid
	}
	// Review prose remains private. The permanent reason contains only its digest.
	content, err := canon.New().Digest(struct{ Text string }{reason})
	if err != nil {
		return domain.Change{}, err
	}
	private, err := eventstore.SealPrivate(s.key, actor.TenantID, uuid.New(), "workflow-v1", []byte(reason))
	if err != nil {
		return domain.Change{}, err
	}
	digest, err := canon.New().Digest(struct {
		Actor         Actor
		Request, Kind string
		Revision      int64
		Content       ports.Digest
	}{actor, request, kind, revision, content})
	if err != nil {
		return domain.Change{}, err
	}
	return s.Store.MutateChange(ctx, eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: request, ID: id, ExpectedRevision: revision, InputDigest: digest, Private: &private}, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		snapshot, err := s.Store.GraphWithin(ctx, tx, actor.TenantID, s.key)
		if err != nil {
			return nil, err
		}
		a, err := s.active(ctx, tx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		result, _, err := impact(snapshot, c.Intent)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.context(ctx, tx, actor, strings.ToLower(kind), ownersFor(a, result)); err != nil {
			return nil, err
		}
		return domain.Decide(c, domain.Command{Kind: kind, At: now, Reason: "review context digest " + content.String(), PrivateReference: private.ID.String()})
	})
}

// Guard rechecks every bound input before dispatch. Until the peer supplies a
// conformant authenticated execution transport, a proved approval is kept in
// review rather than sending it to a connector that ignores the envelope.
func (s *Service) Guard(ctx context.Context, args JobArgs) (err error) {
	var span *telemetry.Span
	defer func() { span.End(err) }()
	digest, err := canon.New().Digest(args)
	if err != nil {
		return err
	}
	var prepared *PreparedCommand
	var preparedAt time.Time
	m := eventstore.ChangeMutation{TenantID: args.Tenant, ActorID: "core-execution-guard", RequestID: args.Request, ID: jobID(args), ExpectedRevision: args.Revision, InputDigest: digest}
	m.Additional = func(tx pgx.Tx, receipt eventstore.Receipt) error {
		if prepared == nil {
			return nil
		}
		if !prepared.GrantExpiresAt.IsZero() {
			if err := s.scheduleGrantExpiry(ctx, tx, GrantExpiryArgs{Tenant: args.Tenant, Request: args.Request, ExecutionID: prepared.CommandID, Digest: prepared.EnvelopeDigest}, prepared.GrantExpiresAt); err != nil {
				return err
			}
		}
		return s.executions[args.Tenant].stage(ctx, tx, *prepared, receipt, preparedAt)
	}
	_, err = s.Store.MutateChange(ctx, m, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		ctx, span = s.observer.Start(ctx, "execution_guard", args.Tenant, c.CorrelationID)
		snapshot, err := s.Store.GraphWithin(ctx, tx, args.Tenant, s.key)
		if err != nil {
			return hold(c, now, "graph unavailable before dispatch")
		}
		a, err := s.active(ctx, tx, args.Tenant)
		if err != nil {
			return hold(c, now, "verified policy unavailable before dispatch")
		}
		if c.Envelope == nil || c.Envelope.GraphVersion != snapshot.Version() || c.Envelope.PolicyDigest != a.Hash || c.Envelope.RegistryEpoch != a.RegistryEpoch || c.Envelope.RegistryDigest != a.RegistryDigest || !now.Before(c.Envelope.ExpiresAt) {
			return domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
		}
		result, delta, err := impact(snapshot, c.Intent)
		if err != nil {
			return hold(c, now, "impact cannot be proved before dispatch")
		}
		hash, err := canon.New().Digest(result)
		if err != nil {
			return nil, err
		}
		if hash != c.Envelope.ImpactDigest {
			return domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
		}
		decision, err := s.decidePolicy(ctx, c.TenantID, c.CorrelationID, a, factsFor(ctx, snapshot, a, c, result))
		if err != nil {
			return hold(c, now, "policy reevaluation unavailable")
		}
		if c.Intent.Emergency && c.Intent.DurationSeconds <= 0 {
			return hold(c, now, "emergency access requires a fixed duration")
		}
		if scope := scopeReview(c.Intent, result); scope != nil && (!scope.Complete || scope.OverBroad) {
			return hold(c, now, "explicit requested scope cannot be satisfied without excess access")
		}
		if decision.Outcome != c.Decision.Outcome || decision.Quorum != c.Decision.Quorum || !slices.Equal(decision.Groups, c.Decision.Groups) {
			return domain.Decide(c, domain.Command{Kind: "CONTEXT_CHANGED", At: now, Reason: "context changed"})
		}
		requesterGroups, err := groups(snapshot, c.Requester)
		if err != nil || a.Authorize(ctx, policy.Facts{Actor: c.Requester, Operation: "submit", Groups: requesterGroups}) != nil {
			return hold(c, now, "requester authorization changed")
		}
		if s.approvals == nil {
			return hold(c, now, "conformant passkey dependency unavailable")
		}
		if len(c.Approvals) < max(1, c.Decision.Quorum) {
			return hold(c, now, "passkey-confirmed independent authorization required")
		}
		for _, approval := range c.Approvals {
			memberships, err := groups(snapshot, approval.ActorID)
			if err != nil || a.Authorize(ctx, policy.Facts{Actor: approval.ActorID, Operation: "approve", Groups: memberships, Owners: ownersFor(a, result)}) != nil {
				return hold(c, now, "approver authorization changed")
			}
			if err := eligible(snapshot, c, result, delta, approval.ActorID, ownersFor(a, result)); err != nil {
				return hold(c, now, "approval independence changed")
			}
			verified, err := s.approvals.Verify(ctx, approval.Evidence, c.Digest)
			if err != nil || !verified.UserVerified || verified.ActorID != approval.ActorID || verified.TenantID != c.TenantID || verified.ChangeDigest != c.Digest || !slices.Equal(verified.CredentialID, approval.CredentialID) {
				return hold(c, now, "approval no longer valid")
			}
		}
		execution := s.executions[args.Tenant]
		if execution == nil {
			return hold(c, now, "authenticated connector execution/read-back contract unavailable")
		}
		id := uuid.NewSHA1(jobID(args), []byte("execute")).String()
		command, err := execution.prepare(ctx, tx, c, id, now)
		if err != nil {
			return hold(c, now, "connector preconditions or capability unavailable")
		}
		prepared = &command
		preparedAt = now
		events, err := domain.Decide(c, domain.Command{Kind: "DISPATCH", At: now, Digest: c.Digest, ExecutionID: id, GrantExpiresAt: command.GrantExpiresAt})
		if err != nil {
			return nil, err
		}
		return events, s.scheduleReconciliation(ctx, tx, c, now)
	})
	if errors.Is(err, eventstore.ErrVersionConflict) {
		return nil
	}
	return err
}

func (s *Service) View(ctx context.Context, actor Actor, request string) (domain.Change, error) {
	if err := s.Authorize(ctx, actor, "view"); err != nil {
		return domain.Change{}, err
	}
	c, err := s.Store.ReadChange(ctx, actor.TenantID, request)
	if err != nil {
		return c, err
	}
	_, err = s.ResponseDetail(ctx, actor, c)
	return c, err
}
func (s *Service) PrivateContext(ctx context.Context, c domain.Change) (string, error) {
	raw, err := s.Store.ReadPrivate(ctx, c.TenantID, c.PrivateReference, s.key)
	return string(raw), err
}

func (s *Service) ProvideContext(ctx context.Context, actor Actor, request string, id uuid.UUID, revision int64, text string) (domain.Change, error) {
	if len(strings.TrimSpace(text)) < 10 || len(text) > 4000 {
		return domain.Change{}, domain.ErrInvalid
	}
	content, err := canon.New().Digest(struct {
		Context string `json:"context"`
	}{text})
	if err != nil {
		return domain.Change{}, err
	}
	private, err := eventstore.SealPrivate(s.key, actor.TenantID, uuid.New(), "workflow-v1", []byte(text))
	if err != nil {
		return domain.Change{}, err
	}
	digest, err := canon.New().Digest(struct {
		Actor    Actor
		Request  string
		Revision int64
		Content  ports.Digest
	}{actor, request, revision, content})
	if err != nil {
		return domain.Change{}, err
	}
	return s.Store.MutateChange(ctx, eventstore.ChangeMutation{TenantID: actor.TenantID, ActorID: actor.ID, RequestID: request, ID: id, ExpectedRevision: revision, InputDigest: digest, Private: &private}, func(tx pgx.Tx, now time.Time, c domain.Change) ([]domain.Event, error) {
		if c.Requester != actor.ID {
			return nil, ErrPermission
		}
		if _, _, err := s.context(ctx, tx, actor, "submit", nil); err != nil {
			return nil, err
		}
		events, err := domain.Decide(c, domain.Command{Kind: "PROVIDE_CONTEXT", At: now, PrivateReference: private.ID.String(), PrivateDigest: content})
		if err != nil {
			return nil, err
		}
		if err := s.enqueue(ctx, tx, JobArgs{actor.TenantID, request, c.Revision + 1, "assess"}); err != nil {
			return nil, err
		}
		return events, nil
	})
}
func (s *Service) List(ctx context.Context, actor Actor, after int64, limit int, status string, expectedPosition int64) ([]domain.Change, int64, int64, error) {
	if limit < 1 || limit > 201 || after < 0 {
		return nil, 0, 0, domain.ErrInvalid
	}
	result := []domain.Change{}
	last := after
	var position int64
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, actor.TenantID).Scan(&position); err != nil {
			return err
		}
		if expectedPosition != 0 && expectedPosition != position {
			return domain.ErrContextChanged
		}
		snapshot, active, err := s.context(ctx, tx, actor, "view", nil)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT request_id::text,event_position FROM ratchet.change_projection WHERE tenant_id=$1 AND event_position>$2 AND ($3='' OR state=$3) ORDER BY event_position,request_id LIMIT $4`, actor.TenantID, after, status, limit)
		if err != nil {
			return err
		}
		type ref struct {
			id       string
			position int64
		}
		refs := []ref{}
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.id, &r.position); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, r := range refs {
			c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, r.id)
			if err != nil {
				return err
			}
			last = r.position
			if _, err := visibility(ctx, actor, c, snapshot, active); errors.Is(err, ErrPermission) {
				continue
			} else if err != nil {
				return err
			}
			result = append(result, c)
		}
		return nil
	})
	return result, last, position, err
}
