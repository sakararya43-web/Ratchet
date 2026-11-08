//go:build integration

package workflow_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestApprovalReviewRequiresIndependentVisibilityAndExactBoundImpact(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	start(t, service, sys.ctx)
	requester := workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}
	created, err := service.Submit(sys.ctx, requester, workflow.Submit{Intent: domain.Intent{Kind: "ROLE_ASSIGN", Target: requester.ID, Access: "role:finance"}, Justification: "Review exact impact without organization graph access", CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	c := waitState(t, sys, created.ID, domain.AwaitingApproval)
	owner := workflow.Actor{TenantID: sys.tenant, ID: "user:owner"}
	review, err := service.ApprovalReview(sys.ctx, owner, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canon.New().Digest(review.Impact)
	if err != nil || digest != c.Envelope.ImpactDigest || review.Digest != c.Digest.String() || review.Revision != c.Revision {
		t.Fatal("review unbound from approved context", err)
	}
	if _, err = service.ApprovalReview(sys.ctx, requester, c.ID); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("requester received independent review detail", err)
	}
	if _, err = service.Review(sys.ctx, owner, c.ID, uuid.New(), c.Revision, "HOLD", "Independent review hold"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ApprovalReview(sys.ctx, owner, c.ID); !errors.Is(err, domain.ErrContextChanged) {
		t.Fatal("held request supplied live approval review", err)
	}
}
