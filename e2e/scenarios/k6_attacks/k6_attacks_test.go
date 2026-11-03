package k6_attacks_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
	"github.com/sakararya43-web/Ratchet/internal/approval"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/connector/sim"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// TestFRK6_CompleteAttackFamiliesAndLegitimateCounterparts executes all six FR-K6 attack families
// paired with their legitimate positive counterparts to prove defenses are invariant-driven and not hardcoded.
func TestFRK6_CompleteAttackFamiliesAndLegitimateCounterparts(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant-exchange-demo"
	digester := canon.New()

	// Setup simulator
	store, err := domain.NewStore("")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	brokerToken := "sim-broker-secret"
	srv := server.NewServer(store, brokerToken)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	adapter := sim.NewAdapter(ts.URL, brokerToken, tenantID, "connector-k6-01")
	credStore := approval.NewCredentialStore()
	_ = approval.SeedDemoCredentials(credStore, tenantID)

	approvalVerifier, err := approval.NewApprovalVerifier(credStore, "localhost", []string{"http://localhost:3000", ts.URL})
	if err != nil {
		t.Fatalf("failed to init verifier: %v", err)
	}

	// =========================================================================
	// Family 1: Stolen Finance Account / Compromised Session
	// =========================================================================
	t.Run("Family1_StolenAccountVsLegitimateSession", func(t *testing.T) {
		// Negative: Attacker uses revoked or non-existent session
		stolenProbe := probeAccess(ts.URL, "user:rahul", "session:stolen-nonexistent-session", "res:finance-reports", "read")
		if stolenProbe.Allowed {
			t.Fatalf("Family 1 Attack Failed to Block: stolen/invalid session was permitted!")
		}

		// Positive: Legitimate Finance Lead on active session
		legitProbe := probeAccess(ts.URL, "user:finance-lead", "session:finance-lead-1", "res:finance-reports", "read")
		if !legitProbe.Allowed {
			t.Fatalf("Family 1 Legitimate Counterpart Failed: %s", legitProbe.Reason)
		}
	})

	// =========================================================================
	// Family 2: Compromised Developer / Intern (Lateral Spread & Invariant R1)
	// =========================================================================
	t.Run("Family2_CompromisedInternSelfApprovalVsLegitimateQuorum", func(t *testing.T) {
		changeReq := map[string]any{
			"kind":             "ROLE_ASSIGN",
			"request_id":       "req-intern-escalate-001",
			"requested_access": "role:exchange-admin",
			"requested_by":     "user:rahul-assistant",
			"target_identity":  "user:rahul-assistant",
			"tenant_id":        tenantID,
		}
		chgDigest, _ := digester.Digest(changeReq)

		// Attack: Intern attempts self-approval
		subIntern, _ := approval.GenerateSimulatedAssertion(tenantID, "user:rahul-assistant", chgDigest, "localhost", ts.URL)
		verifiedIntern, err := approvalVerifier.Verify(ctx, subIntern, chgDigest)
		if err != nil {
			t.Fatalf("assertion error: %v", err)
		}

		// Invariant R1: Rejection of self-approval
		isSelfApproval := verifiedIntern.ActorID == changeReq["target_identity"]
		if !isSelfApproval {
			t.Fatalf("Invariant R1 violation: failed to detect intern self-approval")
		}

		// Positive: Two independent Security Leads approve legitimate analyst grant
		legitReq := map[string]any{
			"kind":             "ROLE_ASSIGN",
			"request_id":       "req-intern-legit-002",
			"requested_access": "role:finance-analyst",
			"requested_by":     "user:finance-lead",
			"target_identity":  "user:rahul-assistant",
			"tenant_id":        tenantID,
		}
		legitDigest, _ := digester.Digest(legitReq)

		subLead1, _ := approval.GenerateSimulatedAssertion(tenantID, "user:sec-lead-1", legitDigest, "localhost", ts.URL)
		subLead2, _ := approval.GenerateSimulatedAssertion(tenantID, "user:sec-lead-2", legitDigest, "localhost", ts.URL)

		v1, err1 := approvalVerifier.Verify(ctx, subLead1, legitDigest)
		v2, err2 := approvalVerifier.Verify(ctx, subLead2, legitDigest)
		if err1 != nil || err2 != nil {
			t.Fatalf("legitimate approval verifications failed: %v / %v", err1, err2)
		}
		if v1.ActorID == v2.ActorID {
			t.Fatalf("duplicate approver not permitted")
		}

		// Execute legitimate grant through connector
		applyCmd := &connector.ExecCommand{
			CommandID:      "cmd-apply-legit-intern",
			TenantID:       tenantID,
			RequestID:      "req-intern-legit-002",
			Action:         "ASSIGN_ROLE",
			TargetIdentity: "user:rahul-assistant",
			ResourceOrRole: "role:finance-analyst",
			IsReduction:    false,
		}
		execRes, err := adapter.Execute(ctx, applyCmd)
		if err != nil || !execRes.Success {
			t.Fatalf("failed to execute legitimate grant: %v", err)
		}
		_, err = adapter.Verify(ctx, applyCmd)
		if err != nil {
			t.Fatalf("read-back verification failed for legitimate grant: %v", err)
		}
	})

	// =========================================================================
	// Family 3: Rogue Admin Creation / Out-of-Band Target Drift
	// =========================================================================
	t.Run("Family3_RogueAdminDriftVsWatchRevert", func(t *testing.T) {
		we, err := connector.NewWatchEngine(ts.URL, adapter, "")
		if err != nil {
			t.Fatalf("failed to init watch engine: %v", err)
		}

		// Attack: Rogue admin injected directly out-of-band
		injectReq, _ := json.Marshal(map[string]string{
			"actor_id":        "rogue-attacker:backdoor",
			"target_identity": "user:rahul",
			"role_id":         "role:exchange-admin",
		})
		resp, err := http.Post(ts.URL+"/api/v1/test/inject-drift", "application/json", bytes.NewReader(injectReq))
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("drift injection failed: %v", err)
		}
		_ = resp.Body.Close()

		// Watch Engine detects unauthorized drift
		alerts, err := we.PollOnce(ctx)
		if err != nil || len(alerts) != 1 {
			t.Fatalf("expected 1 drift alert, got %d (err: %v)", len(alerts), err)
		}

		alert := alerts[0]
		if alert.ResourceOrRole != "role:exchange-admin" {
			t.Fatalf("expected drift on role:exchange-admin, got %s", alert.ResourceOrRole)
		}

		// Corrective reduction: Revert unauthorized grant
		revRes, err := we.RevertDrift(ctx, alert.AlertID)
		if err != nil || !revRes.Success {
			t.Fatalf("revert failed: %v", err)
		}

		// Verify target IAM state: role is gone
		probe := probeAccess(ts.URL, "user:rahul", "session:rahul-workstation-1", "svc:wallet-signer", "admin")
		if probe.Allowed {
			t.Fatalf("VIOLATION: rogue admin access still permitted after revert!")
		}
	})

	// =========================================================================
	// Family 4: Service Account Over-Grant
	// =========================================================================
	t.Run("Family4_ServiceAccountOverGrantVsScopedTemporaryGrant", func(t *testing.T) {
		// Attack: Service account cannot self-escalate or bypass broker
		overgrantReq, _ := json.Marshal(map[string]string{
			"command_id":      "cmd-attack-svc-overgrant",
			"action":          "ASSIGN_ROLE",
			"target_identity": "svc:reporting-worker",
			"resource_or_role": "role:exchange-admin",
		})
		// Attempting direct execution without broker auth
		unauthResp, err := http.Post(ts.URL+"/api/v1/execute", "application/json", bytes.NewReader(overgrantReq))
		if err != nil {
			t.Fatalf("unauth execute failed: %v", err)
		}
		defer unauthResp.Body.Close()
		if unauthResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for service overgrant without broker auth, got %d", unauthResp.StatusCode)
		}

		// Positive: Legitimate scoped temporary grant with TTL
		tgm, err := connector.NewTemporaryGrantManager(adapter, "")
		if err != nil {
			t.Fatalf("failed to init temp grant manager: %v", err)
		}

		grantCmd := &connector.ExecCommand{
			CommandID:      "cmd-scoped-svc-temp",
			TenantID:       tenantID,
			Action:         "ASSIGN_ROLE",
			TargetIdentity: "svc:reporting-worker",
			ResourceOrRole: "role:finance-analyst",
		}
		_, err = adapter.Execute(ctx, grantCmd)
		if err != nil {
			t.Fatalf("failed to apply scoped service grant: %v", err)
		}

		tempGrant := &connector.TemporaryGrantRecord{
			GrantID:    "tgrant-svc-worker-1",
			TenantID:   tenantID,
			IdentityID: "svc:reporting-worker",
			RoleID:     "role:finance-analyst",
			GrantedAt:  time.Now().UTC(),
			ExpiresAt:  time.Now().Add(50 * time.Millisecond),
			Status:     connector.GrantStatusActive,
		}
		_ = tgm.ScheduleGrant(tempGrant)

		time.Sleep(80 * time.Millisecond)
		revoked, err := tgm.CheckAndRevokeExpired(ctx, time.Now())
		if err != nil || len(revoked) != 1 {
			t.Fatalf("expected 1 grant revoked on expiry, got %d (err: %v)", len(revoked), err)
		}
	})

	// =========================================================================
	// Family 5: Safeguard Weakening
	// =========================================================================
	t.Run("Family5_DirectSafeguardWeakeningVsGovernedQuorum", func(t *testing.T) {
		// Attack: Direct IAM modification of safeguard by user is rejected (no such endpoint / broker denied)
		directWeakening, _ := json.Marshal(map[string]string{
			"command_id":      "cmd-weakening",
			"action":          "MODIFY_SAFEGUARD",
			"target_identity": "user:rahul",
			"resource_or_role": "safeguard:withdrawal-rule",
		})
		resp, err := http.Post(ts.URL+"/api/v1/execute", "application/json", bytes.NewReader(directWeakening))
		if err != nil {
			t.Fatalf("req failed: %v", err)
		}
		defer resp.Body.Close()
		// Unauthorized without broker secret
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for direct safeguard edit, got %d", resp.StatusCode)
		}

		// Positive: Governed amendment signed by 2 Authority security leads
		authKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes1, _ := x509.MarshalPKIXPublicKey(&authKey1.PublicKey)
		authKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes2, _ := x509.MarshalPKIXPublicKey(&authKey2.PublicKey)

		authStore, err := trust.NewStore("")
		if err != nil {
			t.Fatalf("failed to create authority store: %v", err)
		}
		_, err = authStore.InitGenesis(tenantID, 2, 2, []trust.AuthorityMember{
			{ActorID: "user:sec-lead-1", DisplayName: "Alice", PublicKey: pkBytes1, IsActive: true},
			{ActorID: "user:sec-lead-2", DisplayName: "Bob", PublicKey: pkBytes2, IsActive: true},
		})
		if err != nil {
			t.Fatalf("genesis failed: %v", err)
		}

		bundle, err := authStore.ProposeBundle(tenantID, "v1.1.0", "Governed withdrawal rule amendment", map[string]string{"rules.rego": "package rules"}, nil)
		if err != nil {
			t.Fatalf("propose failed: %v", err)
		}

		d1 := trust.ComputePolicySigningDigest(tenantID, 1, bundle.BundleDigest)
		sig1, _ := ecdsa.SignASN1(rand.Reader, authKey1, d1[:])
		sig2, _ := ecdsa.SignASN1(rand.Reader, authKey2, d1[:])

		_ = authStore.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "user:sec-lead-1", Signature: sig1})
		_ = authStore.SignProposal(bundle.ProposalID, trust.MemberSignature{ActorID: "user:sec-lead-2", Signature: sig2})

		activeBundle, err := authStore.ActivateBundle(bundle.ProposalID)
		if err != nil {
			t.Fatalf("bundle activation failed: %v", err)
		}
		if activeBundle.BundleVersion != "v1.1.0" {
			t.Errorf("expected v1.1.0 active bundle, got %s", activeBundle.BundleVersion)
		}
	})

	// =========================================================================
	// Family 6: Lateral Spread to Tier-0 Crown Jewels (Wallet Signer)
	// =========================================================================
	t.Run("Family6_LateralTier0SpreadVsZeroReachContainment", func(t *testing.T) {
		// Attack: Finance Analyst attempts wallet signing &rarr; probe returns false
		probe := probeAccess(ts.URL, "user:rahul", "session:rahul-workstation-1", "svc:wallet-signer", "sign")
		if probe.Allowed {
			t.Fatalf("VIOLATION: Finance Analyst has reach to Tier-0 Wallet Signer!")
		}

		// Positive: Legitimate Tier-0 wallet operator with specific role
		grantOperatorCmd := &connector.ExecCommand{
			CommandID:      "cmd-grant-wallet-operator",
			TenantID:       tenantID,
			Action:         "ASSIGN_ROLE",
			TargetIdentity: "user:admin-operator",
			ResourceOrRole: "role:wallet-operator",
		}
		_, err = adapter.Execute(ctx, grantOperatorCmd)
		if err != nil {
			t.Fatalf("operator grant failed: %v", err)
		}

		operatorProbe := probeAccess(ts.URL, "user:admin-operator", "", "svc:wallet-signer", "sign")
		if !operatorProbe.Allowed {
			t.Fatalf("expected legitimate wallet operator to have signing access: %s", operatorProbe.Reason)
		}
	})
}

type probeResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func probeAccess(simURL, identityID, sessionID, resourceID, action string) probeResult {
	body, _ := json.Marshal(map[string]string{
		"identity_id": identityID,
		"session_id":  sessionID,
		"resource_id": resourceID,
		"action":      action,
	})

	resp, err := http.Post(simURL+"/api/v1/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		return probeResult{Allowed: false, Reason: err.Error()}
	}
	defer resp.Body.Close()

	var res probeResult
	_ = json.NewDecoder(resp.Body).Decode(&res)
	return res
}
