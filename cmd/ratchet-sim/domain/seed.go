package domain

import "time"

// FixedSeedTime provides a deterministic base timestamp for seed fixtures.
var FixedSeedTime = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

// NewSeedOrgState generates the initial state of the simulated crypto exchange.
func NewSeedOrgState() *OrgState {
	return &OrgState{
		TenantID: "tenant-exchange-demo",
		Revision: 1000,
		Identities: []Identity{
			{
				ID:          "user:rahul",
				Type:        NodeHuman,
				DisplayName: "Rahul Sharma",
				Department:  "finance",
				Email:       "rahul@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"location":  "Singapore",
					"job_title": "Senior Financial Analyst",
				},
			},
			{
				ID:          "user:rahul-assistant",
				Type:        NodeHuman,
				DisplayName: "Finance Intern (Rahul Team)",
				Department:  "finance",
				Email:       "intern-finance@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"supervisor": "user:rahul",
				},
			},
			{
				ID:          "user:finance-lead",
				Type:        NodeHuman,
				DisplayName: "Priya Patel (Finance Lead)",
				Department:  "finance",
				Email:       "priya.finance@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"job_title": "Head of Financial Operations",
				},
			},
			{
				ID:          "user:sec-lead-1",
				Type:        NodeHuman,
				DisplayName: "Alice Vance (Security Lead 1)",
				Department:  "security",
				Email:       "alice.sec@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"job_title": "Principal Security Engineer",
					"authority": "true",
				},
			},
			{
				ID:          "user:sec-lead-2",
				Type:        NodeHuman,
				DisplayName: "Bob Chen (Security Lead 2)",
				Department:  "security",
				Email:       "bob.sec@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"job_title": "Head of Information Security",
					"authority": "true",
				},
			},
			{
				ID:          "user:admin-operator",
				Type:        NodeHuman,
				DisplayName: "David Kim (Platform Admin)",
				Department:  "infrastructure",
				Email:       "david.infra@cryptox.internal",
				IsDisabled:  false,
				Properties: map[string]string{
					"job_title": "Site Reliability Engineer",
				},
			},
			{
				ID:          "svc:withdrawal-worker",
				Type:        NodeServiceAccount,
				DisplayName: "Automated Withdrawal Processor",
				Department:  "payments",
				IsDisabled:  false,
				Properties: map[string]string{
					"runtime": "k8s-pod",
				},
			},
			{
				ID:          "svc:reporting-worker",
				Type:        NodeServiceAccount,
				DisplayName: "Nightly Analytics Worker",
				Department:  "data",
				IsDisabled:  false,
				Properties: map[string]string{
					"runtime": "cronjob",
				},
			},
		},
		Roles: []Role{
			{
				ID:          "role:finance-analyst",
				DisplayName: "Finance Analyst",
				Description: "Read-only access to daily finance ledgers and report exports",
				Permissions: []string{
					"res:finance-reports:read",
					"res:daily-exchange-ledger:read",
				},
			},
			{
				ID:          "role:finance-lead",
				DisplayName: "Finance Lead",
				Description: "Manage financial reporting and approve report dissemination",
				Permissions: []string{
					"res:finance-reports:read",
					"res:finance-reports:approve",
					"res:daily-exchange-ledger:read",
				},
			},
			{
				ID:          "role:security-lead",
				DisplayName: "Security Lead",
				Description: "Review security policies and independent escalation governance",
				Permissions: []string{
					"policy:review",
					"audit:inspect",
				},
			},
			{
				ID:          "role:wallet-operator",
				DisplayName: "Wallet Operator (Tier-0)",
				Description: "Direct signing capability on cryptocurrency wallet signing service",
				Permissions: []string{
					"svc:wallet-signer:sign",
				},
			},
			{
				ID:          "role:exchange-admin",
				DisplayName: "Exchange Super Admin (Tier-0)",
				Description: "Full administrative control over exchange systems, DBs, and signing services",
				Permissions: []string{
					"svc:wallet-signer:admin",
					"res:customer-db:admin",
					"safeguard:withdrawal-rule:modify",
					"iam:all",
				},
			},
		},
		Resources: []Resource{
			{
				ID:          "svc:wallet-signer",
				Type:        "service",
				Tier:        0, // Crown Jewel
				DisplayName: "Cryptocurrency Hot/Cold Wallet Signer",
				Description: "Authorizes and signs blockchain withdrawal transactions",
			},
			{
				ID:          "res:customer-db",
				Type:        "database",
				Tier:        0, // Crown Jewel
				DisplayName: "Customer Account & KYC Database",
				Description: "Houses customer identities, private keys, and user balances",
			},
			{
				ID:          "res:finance-reports",
				Type:        "storage_bucket",
				Tier:        2,
				DisplayName: "Financial Auditing & Reporting Bucket",
				Description: "Contains quarterly finance summaries and compliance reports",
			},
			{
				ID:          "res:daily-exchange-ledger",
				Type:        "database_view",
				Tier:        2,
				DisplayName: "Daily Exchange Trading Ledger",
				Description: "Read-only ledger view of daily matched exchange trades",
			},
			{
				ID:          "res:staging-env",
				Type:        "environment",
				Tier:        3,
				DisplayName: "Internal Staging Sandbox",
				Description: "Non-production testing cluster",
			},
		},
		Safeguards: []Safeguard{
			{
				ID:          "safeguard:withdrawal-rule",
				Tier:        0,
				DisplayName: "Dual-Control Withdrawal Threshold Rule",
				Description: "Enforces dual authorization for any crypto transaction exceeding $10,000 equivalent",
				ProtectedResources: []string{
					"svc:wallet-signer",
				},
				Parameters: map[string]string{
					"threshold_usd":   "10000",
					"required_checks": "2",
				},
			},
			{
				ID:          "safeguard:admin-mfa-policy",
				Tier:        1,
				DisplayName: "Hardware MFA Policy for Admins",
				Description: "Requires FIDO2 WebAuthn authentication for all administrative actions",
				ProtectedResources: []string{
					"role:exchange-admin",
					"res:customer-db",
				},
			},
		},
		Grants: []Grant{
			{
				ID:         "grant:rahul:finance-analyst",
				IdentityID: "user:rahul",
				RoleID:     "role:finance-analyst",
				GrantedAt:  FixedSeedTime,
				GrantedBy:  "user:finance-lead",
			},
			{
				ID:         "grant:priya:finance-lead",
				IdentityID: "user:finance-lead",
				RoleID:     "role:finance-lead",
				GrantedAt:  FixedSeedTime,
				GrantedBy:  "system:init",
			},
			{
				ID:         "grant:alice:security-lead",
				IdentityID: "user:sec-lead-1",
				RoleID:     "role:security-lead",
				GrantedAt:  FixedSeedTime,
				GrantedBy:  "system:init",
			},
			{
				ID:         "grant:bob:security-lead",
				IdentityID: "user:sec-lead-2",
				RoleID:     "role:security-lead",
				GrantedAt:  FixedSeedTime,
				GrantedBy:  "system:init",
			},
		},
		ControlRelations: []ControlRelation{
			{
				ControllerID: "user:rahul",
				ControlledID: "user:rahul-assistant",
				Kind:         "CAN_ADMINISTER",
			},
		},
		Sessions: []Session{
			{
				SessionID:  "session:rahul-workstation-1",
				IdentityID: "user:rahul",
				DeviceID:   "device:sg-macbook-402",
				CreatedAt:  FixedSeedTime.Add(1 * time.Hour),
				LastSeenAt: FixedSeedTime.Add(2 * time.Hour),
				IsRevoked:  false,
			},
			{
				SessionID:  "session:finance-lead-1",
				IdentityID: "user:finance-lead",
				DeviceID:   "device:sg-laptop-101",
				CreatedAt:  FixedSeedTime.Add(30 * time.Minute),
				LastSeenAt: FixedSeedTime.Add(2 * time.Hour),
				IsRevoked:  false,
			},
			{
				SessionID:  "session:intern-workstation-1",
				IdentityID: "user:rahul-assistant",
				DeviceID:   "device:sg-intern-laptop",
				CreatedAt:  FixedSeedTime,
				LastSeenAt: FixedSeedTime,
				IsRevoked:  false,
			},
		},
		AuditLog: []TargetAuditEntry{
			{
				Revision:  1000,
				Timestamp: FixedSeedTime,
				ActorID:   "system:init",
				Action:    "BOOTSTRAP_ORGANIZATION",
				Target:    "tenant-exchange-demo",
				Details: map[string]string{
					"initial_identities": "8",
					"initial_roles":      "5",
				},
			},
		},
	}
}

