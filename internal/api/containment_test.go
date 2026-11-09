package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/api"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

func TestContainmentHandlerRegistrationAndValidation(t *testing.T) {
	// Service nil check
	_, err := api.NewContainmentHandler(nil, map[string]int64{"ROLE_REVOKE": 10})
	if err == nil {
		t.Fatal("expected error for nil service")
	}

	// Cost validation check
	_, err = api.NewContainmentHandler(nil, map[string]int64{"INVALID_ACTION": -1})
	if err == nil {
		t.Fatal("expected error for invalid costs")
	}
}

func TestContainmentHandlerUnauthenticatedRejection(t *testing.T) {
	// Create client against a dummy server to verify RPC method bindings
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := ratchetv1connect.NewContainmentServiceClient(http.DefaultClient, srv.URL)

	// PlanContainment unauthenticated
	_, err := client.PlanContainment(context.Background(), connect.NewRequest(&v1.PlanContainmentRequest{
		TenantId:            "tenant-1",
		CompromisedIdentity: "user:compromised",
	}))
	if err == nil {
		t.Fatal("expected error for unauthenticated plan containment")
	}

	// ExecuteContainment unauthenticated
	_, err = client.ExecuteContainment(context.Background(), connect.NewRequest(&v1.ExecuteContainmentRequest{
		TenantId: "tenant-1",
		PlanId:   "plan-1",
	}))
	if err == nil {
		t.Fatal("expected error for unauthenticated execute containment")
	}

	// RestoreAccess unauthenticated
	_, err = client.RestoreAccess(context.Background(), connect.NewRequest(&v1.RestoreAccessRequest{
		TenantId:   "tenant-1",
		IncidentId: "inc-1",
	}))
	if err == nil {
		t.Fatal("expected error for unauthenticated restore access")
	}
}
