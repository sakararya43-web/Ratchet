package workflow_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestExecuteContainmentInputValidation(t *testing.T) {
	service := &workflow.Service{}
	ctx := context.Background()
	actor := workflow.Actor{TenantID: "tenant-1", ID: "user:sec-lead"}

	// 1. Nil CommandID
	_, err := service.ExecuteContainment(ctx, actor, workflow.ExecuteContainmentInput{
		CommandID:     uuid.Nil,
		PlanID:        uuid.NewString(),
		PlanDigest:    ports.Digest{1},
		AssertionJSON: `{}`,
		ResponderID:   "user:sec-lead",
		CorrelationID: uuid.NewString(),
	})
	if err != domain.ErrInvalid {
		t.Fatalf("expected domain.ErrInvalid for nil CommandID, got %v", err)
	}

	// 2. Empty PlanID
	_, err = service.ExecuteContainment(ctx, actor, workflow.ExecuteContainmentInput{
		CommandID:     uuid.New(),
		PlanID:        "",
		PlanDigest:    ports.Digest{1},
		AssertionJSON: `{}`,
		ResponderID:   "user:sec-lead",
		CorrelationID: uuid.NewString(),
	})
	if err != domain.ErrInvalid {
		t.Fatalf("expected domain.ErrInvalid for empty PlanID, got %v", err)
	}

	// 3. Zero PlanDigest
	_, err = service.ExecuteContainment(ctx, actor, workflow.ExecuteContainmentInput{
		CommandID:     uuid.New(),
		PlanID:        uuid.NewString(),
		PlanDigest:    ports.Digest{},
		AssertionJSON: `{}`,
		ResponderID:   "user:sec-lead",
		CorrelationID: uuid.NewString(),
	})
	if err != domain.ErrInvalid {
		t.Fatalf("expected domain.ErrInvalid for zero PlanDigest, got %v", err)
	}

	// 4. Mismatched ResponderID
	_, err = service.ExecuteContainment(ctx, actor, workflow.ExecuteContainmentInput{
		CommandID:     uuid.New(),
		PlanID:        uuid.NewString(),
		PlanDigest:    ports.Digest{1},
		AssertionJSON: `{}`,
		ResponderID:   "user:impostor",
		CorrelationID: uuid.NewString(),
	})
	if err != workflow.ErrPermission {
		t.Fatalf("expected workflow.ErrPermission for responder mismatch, got %v", err)
	}
}

func TestRestorationIntentValidationRules(t *testing.T) {
	incID := uuid.NewString()

	// 1. Role restoration
	roleRestore := domain.Intent{
		Kind:       "ROLE_ASSIGN",
		Target:     "user:rahul",
		Access:     "role:finance-analyst",
		IncidentID: incID,
	}
	if err := roleRestore.Validate(); err != nil {
		t.Fatalf("valid role restoration failed: %v", err)
	}

	// 2. Account re-enable
	enableAccount := domain.Intent{
		Kind:       "ENABLE_ACCOUNT",
		Target:     "user:rahul",
		IncidentID: incID,
	}
	if err := enableAccount.Validate(); err != nil {
		t.Fatalf("valid enable account failed: %v", err)
	}

	// 3. Service permission restoration
	restorePerm := domain.Intent{
		Kind:       "RESTORE_SERVICE_PERMISSION",
		Target:     "user:rahul",
		Access:     "perm:s3-read",
		IncidentID: incID,
	}
	if err := restorePerm.Validate(); err != nil {
		t.Fatalf("valid restore permission failed: %v", err)
	}

	// 4. Replacement session issuance
	issueSession := domain.Intent{
		Kind:       "ISSUE_SESSION",
		Target:     "user:rahul",
		Access:     "session:replacement-01",
		IncidentID: incID,
	}
	if err := issueSession.Validate(); err != nil {
		t.Fatalf("valid issue session failed: %v", err)
	}

	// 5. Invalid: Empty target
	invalidTarget := domain.Intent{
		Kind:       "ENABLE_ACCOUNT",
		Target:     "",
		IncidentID: incID,
	}
	if err := invalidTarget.Validate(); err == nil {
		t.Fatal("expected error for empty target in ENABLE_ACCOUNT")
	}

	// 6. Invalid: Restore permission without access
	invalidAccess := domain.Intent{
		Kind:       "RESTORE_SERVICE_PERMISSION",
		Target:     "user:rahul",
		Access:     "",
		IncidentID: incID,
	}
	if err := invalidAccess.Validate(); err == nil {
		t.Fatal("expected error for empty access in RESTORE_SERVICE_PERMISSION")
	}

	// 7. Invalid: Non-UUID IncidentID
	invalidInc := domain.Intent{
		Kind:       "ROLE_ASSIGN",
		Target:     "user:rahul",
		Access:     "role:finance",
		IncidentID: "not-a-uuid",
	}
	if err := invalidInc.Validate(); err == nil {
		t.Fatal("expected error for non-UUID IncidentID")
	}
}
