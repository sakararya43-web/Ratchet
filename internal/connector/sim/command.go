package sim

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func protocolDigest(domain string, body any) (ports.Digest, error) {
	return canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{domain, body})
}

// AuthenticateCommand fails closed before any target operation. Only ordinary
// role changes are advertised by the simulator prototype capability.
func AuthenticateCommand(raw []byte, tenant, connector string, public ed25519.PublicKey, now time.Time) (workflow.PreparedCommand, error) {
	return authenticateCommand(raw, tenant, connector, public, now, false)
}

func authenticateCommand(raw []byte, tenant, connector string, public ed25519.PublicKey, now time.Time, allowExpired bool) (workflow.PreparedCommand, error) {
	var c workflow.PreparedCommand
	invalid := func() (workflow.PreparedCommand, error) { return workflow.PreparedCommand{}, eventstore.ErrInvalid }
	if len(raw) == 0 || len(raw) > 1<<20 || len(public) != ed25519.PublicKeySize {
		return invalid()
	}
	if _, err := canon.New().CanonicalizeJSON(raw); err != nil {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF {
		return invalid()
	}
	signature := c.Signature
	c.Signature = nil
	digest, err := protocolDigest("RATCHET_EXEC_COMMAND_V1", c)
	if err != nil || !ed25519.Verify(public, digest[:], signature) {
		return invalid()
	}
	c.Signature = signature
	if c.SchemaVersion != 1 || c.Tenant != tenant || c.Connector != connector || c.ExpectedRevision < 1 || c.Envelope == nil {
		return invalid()
	}
	for _, id := range []string{c.MessageID, c.CommandID, c.RequestID, c.CorrelationID} {
		u, err := uuid.Parse(id)
		if err != nil || u == uuid.Nil {
			return invalid()
		}
	}
	e := c.Envelope
	if e.FormatVersion != 2 || e.TenantID != tenant || e.RequestID != c.RequestID || e.Revision < 1 || e.GraphVersion < 1 || e.Requester == "" || e.ImpactDigest.IsZero() || e.PolicyDigest.IsZero() || e.PrivateDigest.IsZero() || e.PrivateReference == "" {
		return invalid()
	}
	if e.Intent.Validate() != nil {
		return invalid()
	}
	switch c.Purpose {
	case "":
		// Ordinary role operations
		if (e.Intent.Kind != "ROLE_ASSIGN" && e.Intent.Kind != "ROLE_REVOKE") || e.Intent.DurationSeconds != 0 || e.Intent.Emergency || e.Intent.IncidentID != "" {
			return invalid()
		}
		if !c.GrantExpiresAt.IsZero() || c.OriginalCommandID != "" || c.SourceDrift != "" || c.IncidentReference != "" || !c.ReductionDigest.IsZero() || c.Kubernetes != nil {
			return invalid()
		}
	case "CONTAINMENT":
		// Surgical containment reduction operations
		validKinds := map[string]bool{
			"ROLE_REVOKE": true, "RESTRICT_ACCOUNT": true, "TERMINATE_SESSION": true, "REMOVE_SERVICE_PERMISSION": true,
		}
		if !validKinds[e.Intent.Kind] || c.IncidentReference == "" || c.ReductionDigest.IsZero() || c.Kubernetes != nil {
			return invalid()
		}
	case "RESTORE_ACCESS":
		// Restoration operations
		validKinds := map[string]bool{
			"ROLE_ASSIGN": true, "ENABLE_ACCOUNT": true, "ISSUE_SESSION": true, "RESTORE_SERVICE_PERMISSION": true,
		}
		if !validKinds[e.Intent.Kind] || (c.IncidentReference == "" && e.Intent.IncidentID == "") || c.Kubernetes != nil {
			return invalid()
		}
	case "TEMPORARY_GRANT":
		// Phase B1 temporary access
		if e.Intent.Kind != "ROLE_ASSIGN" || e.Intent.DurationSeconds <= 0 || c.GrantExpiresAt.IsZero() || c.Kubernetes != nil {
			return invalid()
		}
	case "EXPIRE_GRANT":
		// Phase B1 timer expiry
		if e.Intent.Kind != "ROLE_REVOKE" || c.OriginalCommandID == "" || c.Kubernetes != nil {
			return invalid()
		}
	case "DRIFT_CORRECTION":
		// Phase B2 drift correction
		if e.Intent.Kind != "ROLE_REVOKE" || c.SourceDrift == "" || c.IncidentReference == "" || c.ReductionDigest.IsZero() || c.Kubernetes != nil {
			return invalid()
		}
	default:
		return invalid()
	}
	if c.DispatchedAt.IsZero() || c.DispatchedAt.After(now.Add(time.Minute)) || !c.Deadline.After(c.DispatchedAt) || !c.Deadline.Equal(e.ExpiresAt) {
		return invalid()
	}
	// Reconciliation is permitted after the deadline, but can never issue a write.
	if !allowExpired && !c.VerifyOnly && !now.Before(c.Deadline) {
		return invalid()
	}
	bound, err := canon.New().Digest(e)
	if err != nil || bound != c.EnvelopeDigest {
		return invalid()
	}
	if e.Intent.Kind == "ROLE_ASSIGN" || e.Intent.Kind == "ROLE_REVOKE" {
		if !canonicalRoles(c.BeforeRoles) || !canonicalRoles(c.ExpectedRoles) {
			return invalid()
		}
		expected := slices.Clone(c.BeforeRoles)
		if e.Intent.Kind == "ROLE_ASSIGN" {
			if !slices.Contains(expected, e.Intent.Access) {
				expected = append(expected, e.Intent.Access)
			}
		} else {
			expected = slices.DeleteFunc(expected, func(role string) bool { return role == e.Intent.Access })
		}
		slices.Sort(expected)
		if !slices.Equal(expected, c.ExpectedRoles) {
			return invalid()
		}
	}
	actors := map[string]bool{}
	for _, a := range c.Approvals {
		if a.ActorID == "" || actors[a.ActorID] || len(a.CredentialID) == 0 || (a.Digest != bound && a.Digest != c.ReductionDigest) || a.VerifiedAt.IsZero() || a.VerifiedAt.After(c.DispatchedAt) {
			return invalid()
		}
		if c.Purpose != "CONTAINMENT" && a.ActorID == e.Requester {
			return invalid()
		}
		actors[a.ActorID] = true
	}
	return c, nil
}
func canonicalRoles(roles []string) bool {
	if len(roles) > 10000 || !slices.IsSorted(roles) {
		return false
	}
	for i, role := range roles {
		if role == "" || (i > 0 && role == roles[i-1]) {
			return false
		}
	}
	return true
}

// commandIdentity permits only a new transport message and the read-only query
// flag to vary. A command ID can never be reused with different approved intent.
func commandIdentity(c workflow.PreparedCommand) (ports.Digest, error) {
	c.Signature = nil
	c.MessageID = ""
	c.VerifyOnly = false
	return protocolDigest("RATCHET_SIM_COMMAND_IDENTITY_V1", c)
}
