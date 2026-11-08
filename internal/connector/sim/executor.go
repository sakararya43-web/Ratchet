package sim

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

type ResultPublisher func(context.Context, string, string, []byte) error

type Executor struct {
	mu                           sync.Mutex
	tenant, connector, directory string
	core                         ed25519.PublicKey
	key                          ed25519.PrivateKey
	adapter                      *Adapter
	publish                      ResultPublisher
}
type commandRecord struct {
	Version  int                                 `json:"version"`
	Identity ports.Digest                        `json:"identity"`
	Command  workflow.PreparedCommand            `json:"command"`
	Results  map[string]workflow.ExecutionResult `json:"results"`
}

func NewExecutor(tenant, connectorID, directory string, core ed25519.PublicKey, key ed25519.PrivateKey, adapter *Adapter, publish ResultPublisher) (*Executor, error) {
	if tenant == "" || connectorID == "" || directory == "" || len(core) != ed25519.PublicKeySize || len(key) != ed25519.PrivateKeySize || adapter == nil || publish == nil {
		return nil, eventstore.ErrInvalid
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	return &Executor{tenant: tenant, connector: connectorID, directory: directory, core: append(ed25519.PublicKey(nil), core...), key: append(ed25519.PrivateKey(nil), key...), adapter: adapter, publish: publish}, nil
}

// Handle stages before target I/O, persists signed results before publication,
// and acknowledges only after JetStream confirms publication. The target's own
// atomic CAS/receipt journal closes the crash gap between mutation and result.
func (e *Executor) Handle(ctx context.Context, raw []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	command, err := authenticateCommand(raw, e.tenant, e.connector, e.core, time.Now().UTC(), true)
	if err != nil {
		return err
	}
	identity, err := commandIdentity(command)
	if err != nil {
		return err
	}
	path := filepath.Join(e.directory, command.CommandID+".json")
	record := commandRecord{Version: 1, Identity: identity, Command: command, Results: map[string]workflow.ExecutionResult{}}
	stored, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(stored, &record) != nil || record.Version != 1 || record.Results == nil {
			return errors.New("corrupt command journal")
		}
		prior, err := commandIdentity(record.Command)
		if err != nil || prior != identity || record.Identity != identity {
			return eventstore.ErrIdempotencyConflict
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if err = connector.WritePrivateJSON(path, record); err != nil {
			return err
		}
	}
	if result, ok := record.Results[command.MessageID]; ok {
		return e.publishResult(ctx, result)
	}
	var action string
	switch command.Envelope.Intent.Kind {
	case "ROLE_REVOKE":
		action = "REVOKE_ROLE"
	case "RESTRICT_ACCOUNT":
		action = "RESTRICT_ACCOUNT"
	case "ENABLE_ACCOUNT":
		action = "ENABLE_ACCOUNT"
	case "TERMINATE_SESSION":
		action = "TERMINATE_SESSION"
	case "ISSUE_SESSION":
		action = "ISSUE_SESSION"
	case "REMOVE_SERVICE_PERMISSION":
		action = "REMOVE_SERVICE_PERMISSION"
	case "RESTORE_SERVICE_PERMISSION":
		action = "RESTORE_SERVICE_PERMISSION"
	default:
		action = "ASSIGN_ROLE"
	}
	target := &connector.ExecCommand{Deadline: command.Deadline, CommandID: command.CommandID, RequestID: command.RequestID, TenantID: command.Tenant, Action: action, TargetIdentity: command.Envelope.Intent.Target, ResourceOrRole: command.Envelope.Intent.Access, ExpectedTargetRevision: command.ExpectedRevision}
	observed, receipt, err := e.adapter.ObserveCommand(ctx, target)
	if err != nil {
		return err
	}
	preimageMatches := true
	switch command.Envelope.Intent.Kind {
	case "ROLE_ASSIGN", "ROLE_REVOKE":
		preimageMatches = slices.Equal(observed.CurrentRoles, command.BeforeRoles)
	case "RESTRICT_ACCOUNT":
		preimageMatches = !observed.IsRestricted
	case "ENABLE_ACCOUNT":
		preimageMatches = observed.IsRestricted
	case "TERMINATE_SESSION":
		preimageMatches = slices.Contains(observed.ActiveSessions, command.Envelope.Intent.Access)
	}

	// Never write during reconciliation or after expiration, and never write over
	// a changed preimage. A recovered receipt is sufficient to skip execution.
	if !command.VerifyOnly && receipt == nil && time.Now().Before(command.Deadline) && observed.ObservedRevision == command.ExpectedRevision && preimageMatches {
		writeCtx, cancel := context.WithDeadline(ctx, command.Deadline)
		_, _ = e.adapter.Execute(writeCtx, target)
		cancel()
		observed, receipt, err = e.adapter.ObserveCommand(ctx, target)
		if err != nil {
			return err
		}
	}
	at := time.Now().UTC()
	result := workflow.ExecutionResult{SchemaVersion: 1, Tenant: command.Tenant, Connector: command.Connector, MessageID: uuid.NewString(), CommandID: command.CommandID, RequestID: command.RequestID, CorrelationID: command.CorrelationID, EnvelopeDigest: command.EnvelopeDigest, ObservedTenant: observed.TenantID, ObservedTarget: observed.TargetIdentity, ObservedRoles: observed.CurrentRoles, ObservedRevision: observed.ObservedRevision, ObservedAt: at}
	if receipt != nil {
		result.AppliedAt = receipt.AppliedAt
		result.Success = receipt.Revision == command.ExpectedRevision+1 && !receipt.AppliedAt.Before(command.DispatchedAt) && !receipt.AppliedAt.After(command.Deadline) && !receipt.AppliedAt.After(at)
		verified := result.Success && observed.ObservedRevision == receipt.Revision
		switch action {
		case "ASSIGN_ROLE":
			verified = verified && slices.Contains(observed.CurrentRoles, command.Envelope.Intent.Access)
		case "REVOKE_ROLE", "REMOVE_SERVICE_PERMISSION":
			verified = verified && !slices.Contains(observed.CurrentRoles, command.Envelope.Intent.Access)
		case "RESTRICT_ACCOUNT":
			verified = verified && observed.IsRestricted
		case "ENABLE_ACCOUNT":
			verified = verified && !observed.IsRestricted
		case "TERMINATE_SESSION":
			verified = verified && !slices.Contains(observed.ActiveSessions, command.Envelope.Intent.Access)
		case "ISSUE_SESSION":
			verified = verified && (command.Envelope.Intent.Access == "" || slices.Contains(observed.ActiveSessions, command.Envelope.Intent.Access))
		case "RESTORE_SERVICE_PERMISSION":
			verified = verified && slices.Contains(observed.CurrentRoles, command.Envelope.Intent.Access)
		default:
			if len(command.ExpectedRoles) > 0 {
				verified = verified && slices.Equal(observed.CurrentRoles, command.ExpectedRoles)
			}
		}
		result.ReadBackVerified = verified
	} else {
		verified := observed.ObservedRevision == command.ExpectedRevision
		if len(command.BeforeRoles) > 0 {
			verified = verified && slices.Equal(observed.CurrentRoles, command.BeforeRoles)
		}
		result.ReadBackVerified = verified
	}
	result.ObservationDigest, err = protocolObservationDigest(result)
	if err != nil {
		return err
	}
	digest, err := protocolDigest("RATCHET_EXEC_RESULT_V1", result)
	if err != nil {
		return err
	}
	result.Signature = ed25519.Sign(e.key, digest[:])
	record.Results[command.MessageID] = result
	if err = connector.WritePrivateJSON(path, record); err != nil {
		return err
	}
	return e.publishResult(ctx, result)
}
func protocolObservationDigest(r workflow.ExecutionResult) (ports.Digest, error) {
	roles := slices.Clone(r.ObservedRoles)
	slices.Sort(roles)
	return canon.New().Digest(struct {
		Tenant, Target string
		Roles          []string
		Revision       int64
		At             time.Time
	}{r.ObservedTenant, r.ObservedTarget, roles, r.ObservedRevision, r.ObservedAt})
}
func (e *Executor) publishResult(ctx context.Context, r workflow.ExecutionResult) error {
	signature := r.Signature
	r.Signature = nil
	digest, err := protocolDigest("RATCHET_EXEC_RESULT_V1", r)
	if err != nil || !ed25519.Verify(e.key.Public().(ed25519.PublicKey), digest[:], signature) {
		return errors.New("corrupt signed result journal")
	}
	r.Signature = signature
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return e.publish(ctx, "ratchet."+e.tenant+".exec.results", r.MessageID, raw)
}
