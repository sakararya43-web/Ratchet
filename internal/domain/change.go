// Package domain contains the pure, replayable change state machine.
package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var ErrInvalid = errors.New("invalid change")
var ErrTransition = errors.New("invalid change transition")
var ErrContextChanged = errors.New("context changed")

type State string

const (
	Submitted        State = "SUBMITTED"
	Assessed         State = "ASSESSED"
	Allowed          State = "ALLOWED"
	AwaitingApproval State = "AWAITING_APPROVAL"
	Held             State = "HELD"
	Rejected         State = "REJECTED"
	Approved         State = "APPROVED"
	Executing        State = "EXECUTING"
	Executed         State = "EXECUTED"
	Failed           State = "FAILED"
	Expired          State = "EXPIRED"
	Revoked          State = "REVOKED"
)

type Intent struct {
	Kind            string            `json:"kind"`
	Target          string            `json:"target_identity"`
	Access          string            `json:"requested_access"`
	Resources       []string          `json:"requested_resources"`
	Permissions     []string          `json:"requested_permissions"`
	Emergency       bool              `json:"emergency"`
	DurationSeconds int64             `json:"time_limit_seconds"`
	IncidentID      string            `json:"incident_id"`
	Parameters      map[string]string `json:"safeguard_parameters"`
	Kubernetes      *KubernetesChange `json:"kubernetes,omitempty"`
}

func (i Intent) Validate() error {
	if i.Kind != "K8S_RBAC_CHANGE" && i.Kubernetes != nil {
		return ErrInvalid
	}
	if strings.TrimSpace(i.Target) == "" || len(i.Target) > 256 || len(i.Access) > 256 || i.DurationSeconds < 0 || i.DurationSeconds > 86400 || len(i.Resources) > 100 || len(i.Permissions) > 100 {
		return ErrInvalid
	}
	for _, values := range [][]string{i.Resources, i.Permissions} {
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || value != strings.TrimSpace(value) || len(value) > 256 || seen[value] {
				return ErrInvalid
			}
			seen[value] = true
		}
	}
	if (i.DurationSeconds > 0 || i.Emergency) && i.Kind != "ROLE_ASSIGN" {
		return ErrInvalid
	}
	switch i.Kind {
	case "K8S_RBAC_CHANGE":
		if i.Kubernetes == nil || i.Kubernetes.Validate() != nil || !opaqueKubernetesKey(i.Target, "object") || i.Access != i.Kubernetes.Operation || len(i.Parameters) != 0 || len(i.Resources) != 0 || len(i.Permissions) != 0 || i.IncidentID != "" {
			return ErrInvalid
		}
	case "ROLE_ASSIGN", "ROLE_REVOKE":
		if i.Access == "" || len(i.Parameters) != 0 {
			return ErrInvalid
		}
	case "MODIFY_SAFEGUARD":
		if len(i.Parameters) == 0 && i.Access != "remove" {
			return ErrInvalid
		}
	case "RESTRICT_ACCOUNT", "ENABLE_ACCOUNT":
		if len(i.Parameters) != 0 {
			return ErrInvalid
		}
	case "TERMINATE_SESSION", "REMOVE_SERVICE_PERMISSION", "RESTORE_SERVICE_PERMISSION", "ISSUE_SESSION":
		if i.Access == "" || len(i.Parameters) != 0 {
			return ErrInvalid
		}
	default:
		return fmt.Errorf("%w: unsupported kind", ErrInvalid)
	}
	if i.IncidentID != "" {
		if _, err := uuid.Parse(i.IncidentID); err != nil {
			return ErrInvalid
		}
	}
	return nil
}

type Decision struct {
	Outcome string   `json:"outcome"`
	Reasons []string `json:"reasons"`
	Groups  []string `json:"approver_groups"`
	Quorum  int      `json:"quorum"`
}

type ScopeReview struct {
	Complete                bool     `json:"complete"`
	OverBroad               bool     `json:"over_broad"`
	Resources               []string `json:"extra_resources"`
	Permissions             []string `json:"extra_permissions"`
	ControlsOtherIdentities bool     `json:"controls_other_identities"`
}

func (d Decision) Validate() error {
	if len(d.Reasons) == 0 || len(d.Reasons) > 100 || d.Quorum < 0 || d.Quorum > 20 {
		return ErrInvalid
	}
	switch d.Outcome {
	case "ALLOW", "HOLD", "REJECT":
		if d.Quorum != 0 || len(d.Groups) != 0 {
			return ErrInvalid
		}
	case "REQUIRE_APPROVAL":
		if d.Quorum < 1 || len(d.Groups) == 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Envelope struct {
	FormatVersion    int          `json:"format_version"`
	TenantID         string       `json:"tenant_id"`
	RequestID        string       `json:"request_id"`
	Revision         int64        `json:"request_revision"`
	Requester        string       `json:"authenticated_requester"`
	Intent           Intent       `json:"intent"`
	GraphVersion     int64        `json:"graph_version"`
	ImpactDigest     ports.Digest `json:"impact_digest"`
	PolicyDigest     ports.Digest `json:"policy_bundle_hash"`
	RegistryEpoch    int64        `json:"registry_epoch,omitempty"`
	RegistryDigest   ports.Digest `json:"registry_digest,omitempty"`
	ExpiresAt        time.Time    `json:"expires_at"`
	PrivateReference string       `json:"private_record_reference"`
	PrivateDigest    ports.Digest `json:"private_content_digest"`
}
type Approval struct {
	ActorID      string                   `json:"actor_id"`
	CredentialID []byte                   `json:"credential_id"`
	Digest       ports.Digest             `json:"change_digest"`
	Evidence     ports.ApprovalSubmission `json:"assertion"`
	VerifiedAt   time.Time                `json:"verified_at"`
}
type Change struct {
	ID                string          `json:"request_id"`
	CorrelationID     string          `json:"correlation_id,omitempty"`
	TenantID          string          `json:"tenant_id"`
	Requester         string          `json:"requester"`
	Intent            Intent          `json:"intent"`
	State             State           `json:"state"`
	Revision          int64           `json:"revision"`
	Decision          Decision        `json:"decision"`
	Facts             json.RawMessage `json:"decision_facts,omitempty"`
	Envelope          *Envelope       `json:"approval_envelope,omitempty"`
	Digest            ports.Digest    `json:"change_digest"`
	Approvals         []Approval      `json:"approvals"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	PrivateReference  string          `json:"private_record_reference"`
	PrivateDigest     ports.Digest    `json:"private_content_digest"`
	ExecutionID       string          `json:"execution_id,omitempty"`
	ReviewReference   string          `json:"review_private_reference,omitempty"`
	ReviewKind        string          `json:"review_kind,omitempty"`
	GrantExpiresAt    time.Time       `json:"grant_expires_at,omitempty"`
	ExpiryExecutionID string          `json:"expiry_execution_id,omitempty"`
	ExpiryStatus      string          `json:"expiry_status,omitempty"`
	Scope             *ScopeReview    `json:"scope_review,omitempty"`
	SourceDrift       string          `json:"source_drift_id,omitempty"`
	IncidentReference string          `json:"incident_reference,omitempty"`
}
type Event struct {
	Type   string `json:"type"`
	Change Change `json:"change"`
}
type Command struct {
	Kind             string
	At               time.Time
	Submission       *Change
	Decision         Decision
	Envelope         *Envelope
	Digest           ports.Digest
	Approval         *Approval
	Reason           string
	ExecutionID      string
	Verified         bool
	Facts            json.RawMessage
	PrivateReference string
	PrivateDigest    ports.Digest
	GrantExpiresAt   time.Time
	Scope            *ScopeReview
}

func clone(c Change) Change {
	raw, _ := json.Marshal(c)
	var copy Change
	_ = json.Unmarshal(raw, &copy)
	return copy
}

// Decide performs no I/O or wall-clock reads. Only a verified workflow boundary
// may issue APPROVE, DISPATCH or VERIFIED; callers cannot supply these via JSON.
func Decide(current Change, cmd Command) ([]Event, error) {
	if cmd.At.IsZero() {
		return nil, ErrInvalid
	}
	next := clone(current)
	emit := func(typ string, state State) Event {
		next.State = state
		next.Revision++
		next.UpdatedAt = cmd.At
		return Event{typ, clone(next)}
	}
	if cmd.Kind == "SUBMIT" {
		if current.ID != "" || cmd.Submission == nil {
			return nil, ErrTransition
		}
		next = clone(*cmd.Submission)
		if _, err := uuid.Parse(next.ID); err != nil || next.TenantID == "" || next.Requester == "" || next.PrivateReference == "" || next.PrivateDigest.IsZero() {
			return nil, ErrInvalid
		}
		if err := next.Intent.Validate(); err != nil {
			return nil, err
		}
		if next.Intent.Kubernetes != nil && next.Intent.Kubernetes.PlanID != next.ID {
			return nil, ErrInvalid
		}
		next.Revision = 0
		next.CreatedAt = cmd.At
		next.Approvals = nil
		next.Envelope = nil
		next.Digest = ports.Digest{}
		next.ExecutionID = ""
		return []Event{emit("ChangeSubmitted", Submitted)}, nil
	}
	if current.ID == "" {
		return nil, ErrTransition
	}
	terminal := slices.Contains([]State{Rejected, Failed, Expired, Revoked}, current.State)
	if cmd.Kind == "EXPIRE" {
		if terminal || current.State == Executed || current.State == Executing || current.Envelope == nil || cmd.At.Before(current.Envelope.ExpiresAt) {
			return nil, ErrTransition
		}
		next.Approvals = nil
		return []Event{emit("ChangeExpired", Expired)}, nil
	}
	if terminal {
		return nil, ErrTransition
	}
	switch cmd.Kind {
	case "PROVIDE_CONTEXT":
		if !slices.Contains([]State{Submitted, Held, AwaitingApproval}, current.State) || cmd.PrivateReference == "" || cmd.PrivateDigest.IsZero() {
			return nil, ErrTransition
		}
		next.PrivateReference = cmd.PrivateReference
		next.ReviewReference = ""
		next.ReviewKind = ""
		next.PrivateDigest = cmd.PrivateDigest
		next.Approvals = nil
		next.Envelope = nil
		next.Digest = ports.Digest{}
		next.Decision = Decision{}
		next.Scope = nil
		return []Event{emit("ChangeContextProvided", Submitted)}, nil
	case "ASSESS":
		if !slices.Contains([]State{Submitted, Held, Assessed, AwaitingApproval, Allowed, Approved}, current.State) {
			return nil, ErrTransition
		}
		if err := cmd.Decision.Validate(); err != nil {
			return nil, err
		}
		next.Decision = cmd.Decision
		next.Scope = cmd.Scope
		next.Facts = cmd.Facts
		next.Envelope = cmd.Envelope
		next.Digest = cmd.Digest
		next.Approvals = nil
		events := []Event{emit("ChangeAssessed", Assessed)}
		state, typ := Held, "ChangeHeld"
		switch cmd.Decision.Outcome {
		case "ALLOW":
			state, typ = Allowed, "ChangeAllowed"
		case "REQUIRE_APPROVAL":
			state, typ = AwaitingApproval, "ChangeAwaitingApproval"
		case "REJECT":
			state, typ = Rejected, "ChangeRejected"
		}
		if state == Allowed || state == AwaitingApproval {
			if next.Envelope == nil || next.Digest.IsZero() || next.Envelope.TenantID != next.TenantID || next.Envelope.RequestID != next.ID || next.Envelope.Requester != next.Requester || !cmd.At.Before(next.Envelope.ExpiresAt) {
				return nil, ErrInvalid
			}
		}
		return append(events, emit(typ, state)), nil
	case "APPROVE":
		if current.State != AwaitingApproval || current.Envelope == nil || !cmd.At.Before(current.Envelope.ExpiresAt) || cmd.Approval == nil {
			return nil, ErrTransition
		}
		a := *cmd.Approval
		if a.ActorID == "" || a.ActorID == current.Requester || a.Digest != current.Digest || len(a.CredentialID) == 0 || a.VerifiedAt.IsZero() {
			return nil, ErrInvalid
		}
		for _, old := range current.Approvals {
			if old.ActorID == a.ActorID || slices.Equal(old.CredentialID, a.CredentialID) {
				return nil, ErrInvalid
			}
		}
		next.Approvals = append(next.Approvals, a)
		events := []Event{emit("ChangeApprovalRecorded", AwaitingApproval)}
		if len(next.Approvals) >= next.Decision.Quorum {
			events = append(events, emit("ChangeApproved", Approved))
		}
		return events, nil
	case "HOLD", "MORE_INFO", "REJECT", "CONTEXT_CHANGED":
		if !slices.Contains([]State{Submitted, Assessed, Held, AwaitingApproval, Allowed, Approved}, current.State) || cmd.Reason == "" {
			return nil, ErrTransition
		}
		next.Approvals = nil
		next.Envelope = nil
		next.Digest = ports.Digest{}
		next.Decision = Decision{Outcome: "HOLD", Reasons: []string{cmd.Reason}}
		if cmd.PrivateReference != "" {
			next.ReviewReference = cmd.PrivateReference
			next.ReviewKind = cmd.Kind
		}
		if cmd.Kind == "REJECT" {
			next.Decision.Outcome = "REJECT"
			return []Event{emit("ChangeRejected", Rejected)}, nil
		}
		typ := "ChangeHeld"
		if cmd.Kind == "MORE_INFO" {
			typ = "ChangeMoreInfoRequested"
		}
		if cmd.Kind == "CONTEXT_CHANGED" {
			typ = "ChangeContextChanged"
		}
		return []Event{emit(typ, Held)}, nil
	case "DISPATCH":
		if (current.State != Approved && current.State != Allowed) || current.Envelope == nil || !cmd.At.Before(current.Envelope.ExpiresAt) || cmd.Digest != current.Digest || cmd.ExecutionID == "" {
			return nil, ErrTransition
		}
		next.ExecutionID = cmd.ExecutionID
		if current.Intent.DurationSeconds > 0 {
			if current.Intent.Kind != "ROLE_ASSIGN" || !cmd.GrantExpiresAt.Equal(cmd.At.Add(time.Duration(current.Intent.DurationSeconds)*time.Second)) {
				return nil, ErrInvalid
			}
			next.GrantExpiresAt = cmd.GrantExpiresAt
			next.ExpiryStatus = "SCHEDULED"
		}
		return []Event{emit("ChangeExecuting", Executing)}, nil
	case "VERIFIED", "EXECUTION_FAILED":
		if current.State != Executing || current.ExecutionID != cmd.ExecutionID || cmd.ExecutionID == "" {
			return nil, ErrTransition
		}
		if cmd.Kind == "VERIFIED" {
			if !cmd.Verified {
				return nil, ErrInvalid
			}
			return []Event{emit("ChangeExecuted", Executed)}, nil
		}
		if cmd.Reason == "" {
			return nil, ErrInvalid
		}
		next.Decision.Reasons = append(next.Decision.Reasons, cmd.Reason)
		return []Event{emit("ChangeExecutionFailed", Failed)}, nil
	case "RECONCILE":
		if current.State != Executing || cmd.ExecutionID != current.ExecutionID {
			return nil, ErrTransition
		}
		return []Event{emit("ChangeReconciliationRequested", Executing)}, nil
	case "EXPIRE_GRANT":
		if current.State != Executed || current.GrantExpiresAt.IsZero() || cmd.At.Before(current.GrantExpiresAt) || current.ExpiryStatus != "SCHEDULED" || cmd.ExecutionID == "" {
			return nil, ErrTransition
		}
		next.ExpiryExecutionID = cmd.ExecutionID
		next.ExpiryStatus = "REVOKING"
		return []Event{emit("ChangeExpiryDispatched", Executed)}, nil
	case "EXPIRY_RECONCILE", "EXPIRY_FAILED", "REVOKE_VERIFIED":
		if current.State != Executed || current.ExpiryStatus != "REVOKING" || current.ExpiryExecutionID != cmd.ExecutionID || cmd.ExecutionID == "" {
			return nil, ErrTransition
		}
		if cmd.Kind == "EXPIRY_RECONCILE" {
			return []Event{emit("ChangeExpiryReconciliationRequested", Executed)}, nil
		}
		if !cmd.Verified {
			return nil, ErrInvalid
		}
		if cmd.Kind == "EXPIRY_FAILED" {
			next.ExpiryStatus = "FAILED"
			next.Decision.Reasons = append(next.Decision.Reasons, "expiry revocation refused; access requires attention")
			return []Event{emit("ChangeExpiryFailed", Executed)}, nil
		}
		next.ExpiryStatus = "REVOKED"
		return []Event{emit("ChangeRevoked", Revoked)}, nil
	default:
		return nil, ErrInvalid
	}
}

func Replay(events []Event) (Change, error) {
	var state Change
	for _, e := range events {
		c := e.Change
		if c.Revision != state.Revision+1 || c.ID == "" || (state.ID != "" && (state.ID != c.ID || state.TenantID != c.TenantID || state.Requester != c.Requester)) {
			return Change{}, ErrInvalid
		}
		state = clone(c)
	}
	return state, nil
}
