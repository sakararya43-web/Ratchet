package connector

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// DriftStatus constants
const (
	DriftDetected     = "DETECTED"
	DriftReverted     = "REVERTED"
	DriftAcknowledged = "ACKNOWLEDGED"
)

// DriftAlert represents an unauthorized target IAM state mutation detected by Watch.
type DriftAlert struct {
	AlertID        string            `json:"alert_id"`
	TenantID       string            `json:"tenant_id"`
	Revision       int64             `json:"revision"`
	Timestamp      time.Time         `json:"timestamp"`
	ActorID        string            `json:"actor_id"`
	Action         string            `json:"action"`
	TargetIdentity string            `json:"target_identity"`
	ResourceOrRole string            `json:"resource_or_role"`
	Details        map[string]string `json:"details,omitempty"`
	Status         string            `json:"status"` // DETECTED, REVERTED, ACKNOWLEDGED
	RevertedAt     *time.Time        `json:"reverted_at,omitempty"`
}

// WatchCursor records the durable progress cursor for the watch stream.
type WatchCursor struct {
	LastRevision int64     `json:"last_revision"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// WatchEngine monitors the simulator audit log for unauthorized drift and handles automated/authorized reverts.
type WatchEngine struct {
	mu            sync.RWMutex
	baseURL       string
	client        *http.Client
	adapter       TargetAdapter
	cursorPath    string
	lastRevision  int64
	knownCommands map[string]bool // command_ids applied by RATCHET connector
	alerts        []DriftAlert
	tenantID      string
	connectorID   string
	signerKey     ed25519.PrivateKey
}

// NewWatchEngine creates and initializes a WatchEngine.
func NewWatchEngine(baseURL string, adapter TargetAdapter, cursorPath string) (*WatchEngine, error) {
	we := &WatchEngine{
		baseURL:       baseURL,
		client:        &http.Client{Timeout: 5 * time.Second},
		adapter:       adapter,
		cursorPath:    cursorPath,
		knownCommands: make(map[string]bool),
		alerts:        make([]DriftAlert, 0),
		tenantID:      "tenant-exchange-demo",
		connectorID:   "connector-sim-01",
	}

	if cursorPath != "" {
		if _, err := os.Stat(cursorPath); err == nil {
			if err := we.loadCursor(); err != nil {
				return nil, fmt.Errorf("failed to load watch cursor: %w", err)
			}
		}
	}

	return we, nil
}

// SetSigner configures the Ed25519 connector private key and identities for authenticated drift reporting.
func (we *WatchEngine) SetSigner(tenantID, connectorID string, key ed25519.PrivateKey) {
	we.mu.Lock()
	defer we.mu.Unlock()
	we.tenantID = tenantID
	we.connectorID = connectorID
	we.signerKey = key
}

// RegisterApprovedCommand registers a command ID issued by RATCHET so it is recognized as legitimate.
func (we *WatchEngine) RegisterApprovedCommand(commandID string) {
	we.mu.Lock()
	defer we.mu.Unlock()
	we.knownCommands[commandID] = true
}

// PollOnce queries the simulator audit stream since the last revision and detects drift.
func (we *WatchEngine) PollOnce(ctx context.Context) ([]DriftAlert, error) {
	we.mu.Lock()
	defer we.mu.Unlock()

	url := fmt.Sprintf("%s/api/v1/audit?since_revision=%d", we.baseURL, we.lastRevision)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit request: %w", err)
	}

	resp, err := we.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach simulator audit endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simulator audit returned HTTP %d", resp.StatusCode)
	}

	var entries []domain.TargetAuditEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode audit entries: %w", err)
	}

	var newAlerts []DriftAlert
	for _, entry := range entries {
		if entry.Revision > we.lastRevision {
			we.lastRevision = entry.Revision
		}

		// Detect out-of-band IAM mutation:
		// Any grant addition ("ASSIGN_ROLE") not performed by the RATCHET connector broker is drift
		if entry.Action == "ASSIGN_ROLE" {
			isConnectorBroker := entry.ActorID == "broker:ratchet-connector"
			roleID := entry.Details["role_id"]
			if !isConnectorBroker {
				alertID := fmt.Sprintf("drift-rev-%d", entry.Revision)
				tID := we.tenantID
				if tID == "" {
					tID = "tenant-exchange-demo"
				}
				alert := DriftAlert{
					AlertID:        alertID,
					TenantID:       tID,
					Revision:       entry.Revision,
					Timestamp:      entry.Timestamp,
					ActorID:        entry.ActorID,
					Action:         entry.Action,
					TargetIdentity: entry.Target,
					ResourceOrRole: roleID,
					Details:        entry.Details,
					Status:         DriftDetected,
				}
				we.alerts = append(we.alerts, alert)
				newAlerts = append(newAlerts, alert)
			}
		}
	}

	if we.cursorPath != "" {
		_ = we.saveCursor()
	}

	return newAlerts, nil
}

// RevertDrift executes an authorized corrective reduction to revoke an unauthorized grant.
func (we *WatchEngine) RevertDrift(ctx context.Context, alertID string) (*ExecResult, error) {
	we.mu.Lock()
	defer we.mu.Unlock()

	var targetAlert *DriftAlert
	for i := range we.alerts {
		if we.alerts[i].AlertID == alertID {
			targetAlert = &we.alerts[i]
			break
		}
	}

	if targetAlert == nil {
		return nil, fmt.Errorf("drift alert %q not found", alertID)
	}

	if targetAlert.Status == DriftReverted {
		return nil, fmt.Errorf("drift alert %q has already been reverted", alertID)
	}

	// Corrective reduction: Revoke the rogue role grant
	revertCmd := &ExecCommand{
		ExpectedTargetRevision: targetAlert.Revision,
		CommandID:              fmt.Sprintf("revert-%s", alertID),
		TenantID:               targetAlert.TenantID,
		RequestID:              alertID,
		Action:                 "REVOKE_ROLE",
		TargetIdentity:         targetAlert.TargetIdentity,
		ResourceOrRole:         targetAlert.ResourceOrRole,
		IsReduction:            true,
	}

	res, err := we.adapter.Execute(ctx, revertCmd)
	if err != nil || res == nil || !res.Success {
		errMsg := "revert execution failed"
		if err != nil {
			errMsg = err.Error()
		} else if res != nil && res.ErrorMessage != "" {
			errMsg = res.ErrorMessage
		}
		return nil, fmt.Errorf("failed to execute corrective reversion: %s", errMsg)
	}

	// Independently verify read-back
	_, err = we.adapter.Verify(ctx, revertCmd)
	if err != nil {
		return nil, fmt.Errorf("read-back verification failed after revert: %w", err)
	}

	now := time.Now().UTC()
	targetAlert.Status = DriftReverted
	targetAlert.RevertedAt = &now

	return res, nil
}

// GetAlerts returns all recorded drift alerts.
func (we *WatchEngine) GetAlerts() []DriftAlert {
	we.mu.RLock()
	defer we.mu.RUnlock()
	out := make([]DriftAlert, len(we.alerts))
	copy(out, we.alerts)
	return out
}

// GetLastRevision returns the current durable cursor revision.
func (we *WatchEngine) GetLastRevision() int64 {
	we.mu.RLock()
	defer we.mu.RUnlock()
	return we.lastRevision
}

func (we *WatchEngine) loadCursor() error {
	data, err := os.ReadFile(we.cursorPath)
	if err != nil {
		return err
	}
	var cur WatchCursor
	if err := json.Unmarshal(data, &cur); err != nil {
		return err
	}
	we.lastRevision = cur.LastRevision
	return nil
}

func (we *WatchEngine) saveCursor() error {
	cur := WatchCursor{
		LastRevision: we.lastRevision,
		UpdatedAt:    time.Now().UTC(),
	}
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(we.cursorPath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	tmp := we.cursorPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, we.cursorPath)
}

// BuildSignedDriftReport constructs and signs a protobuf SignedDriftReport for an unauthorized IAM mutation.
func (we *WatchEngine) BuildSignedDriftReport(entry domain.TargetAuditEntry) (*v1.SignedDriftReport, []byte, error) {
	we.mu.RLock()
	defer we.mu.RUnlock()
	if we.signerKey == nil {
		return nil, nil, fmt.Errorf("signer key not configured on watch engine")
	}
	roleID := entry.Details["role_id"]
	if roleID == "" {
		roleID = entry.Details["resource_or_role"]
	}
	corr := entry.CorrelationID
	if corr == "" {
		corr = uuid.NewString()
	}
	driftID := uuid.NewString()
	eventID := uuid.NewString()
	msgID := uuid.NewString()
	at := entry.Timestamp.UTC().Format(time.RFC3339Nano)

	report := &v1.DriftReport{
		DriftId:          driftID,
		TenantId:         we.tenantID,
		ConnectorId:      we.connectorID,
		ObservedRevision: entry.Revision,
		DetectedAt:       at,
		Severity:         "HIGH",
		Envelope: &v1.ConnectorEnvelope{
			SchemaVersion:  1,
			TenantId:       we.tenantID,
			ConnectorId:    we.connectorID,
			MessageId:      msgID,
			CorrelationId:  corr,
			SourceRevision: entry.Revision,
		},
		UnapprovedOperation: &v1.AuditEvent{
			EventId:       eventID,
			TenantId:      we.tenantID,
			ActorId:       entry.ActorID,
			Action:        entry.Action,
			Target:        entry.Target,
			Timestamp:     at,
			CorrelationId: corr,
			Details:       map[string]string{"resource_or_role": roleID},
		},
	}
	signed := &v1.SignedDriftReport{Report: report}
	digest, err := workflow.DriftSigningDigest(signed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute drift signing digest: %w", err)
	}
	signed.Signature = ed25519.Sign(we.signerKey, digest[:])
	raw, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(signed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal signed drift report: %w", err)
	}
	return signed, raw, nil
}

// PollAndReport inspects the audit stream for drift and publishes authenticated signed drift reports
// to the provided publisher (e.g. JetStream or core service).
func (we *WatchEngine) PollAndReport(ctx context.Context, publisher func(ctx context.Context, tenant string, rawReport []byte) error) ([]DriftAlert, error) {
	alerts, err := we.PollOnce(ctx)
	if err != nil {
		return nil, err
	}
	if publisher != nil {
		we.mu.RLock()
		hasKey := we.signerKey != nil
		tID := we.tenantID
		we.mu.RUnlock()
		if hasKey {
			for _, alert := range alerts {
				entry := domain.TargetAuditEntry{
					Revision:      alert.Revision,
					Timestamp:     alert.Timestamp,
					ActorID:       alert.ActorID,
					Action:        alert.Action,
					Target:        alert.TargetIdentity,
					Details:       alert.Details,
					CorrelationID: alert.AlertID,
				}
				_, raw, err := we.BuildSignedDriftReport(entry)
				if err != nil {
					return alerts, err
				}
				if err := publisher(ctx, tID, raw); err != nil {
					return alerts, err
				}
			}
		}
	}
	return alerts, nil
}
