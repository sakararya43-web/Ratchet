package k8s

import (
	"strings"
	"time"
)

// Standard Kubernetes RBAC Escalation Verbs and Resources
const (
	VerbBind             = "bind"
	VerbEscalate         = "escalate"
	VerbImpersonate      = "impersonate"
	ResourceRoles        = "roles"
	ResourceClusterRoles = "clusterroles"
	ResourceTokens       = "serviceaccounts/token"
)

// PolicyRule defines permissions for a Role or ClusterRole.
type PolicyRule struct {
	APIGroups []string `json:"apiGroups,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Verbs     []string `json:"verbs"`
}

// Role represents a namespaced Kubernetes Role.
type Role struct {
	Name      string       `json:"name"`
	Namespace string       `json:"namespace"`
	Rules     []PolicyRule `json:"rules"`
}

// ClusterRole represents a cluster-scoped Kubernetes ClusterRole.
type ClusterRole struct {
	Name  string       `json:"name"`
	Rules []PolicyRule `json:"rules"`
}

// Subject represents a Kubernetes identity bound by a RoleBinding.
type Subject struct {
	Kind      string `json:"kind"` // User, Group, ServiceAccount
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// RoleRef points to the Role or ClusterRole being bound.
type RoleRef struct {
	APIGroup string `json:"apiGroup"`
	Kind     string `json:"kind"` // Role or ClusterRole
	Name     string `json:"name"`
}

// RoleBinding binds subjects to a Role or ClusterRole within a namespace.
type RoleBinding struct {
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	RoleRef   RoleRef   `json:"roleRef"`
	Subjects  []Subject `json:"subjects"`
}

// AdmissionReview encapsulates the Kubernetes admission review envelope.
type AdmissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest contains details of the incoming object admission.
type AdmissionRequest struct {
	UID       string         `json:"uid"`
	Kind      map[string]string `json:"kind"`
	Resource  map[string]string `json:"resource"`
	Operation string         `json:"operation"` // CREATE, UPDATE, DELETE
	UserInfo  map[string]any `json:"userInfo"`
	Object    map[string]any `json:"object,omitempty"`
	OldObject map[string]any `json:"oldObject,omitempty"`
}

// AdmissionResponse contains the admission decision.
type AdmissionResponse struct {
	UID     string           `json:"uid"`
	Allowed bool             `json:"allowed"`
	Status  *AdmissionStatus `json:"status,omitempty"`
}

// AdmissionStatus explains why an admission was rejected or accepted.
type AdmissionStatus struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
}

// EscalationFinding reports detected escalation primitives in RBAC rules.
type EscalationFinding struct {
	RuleIndex int
	Primitive string
	Details   string
}

// DetectEscalationPrimitives scans PolicyRules for known privilege escalation primitives:
// 1. "bind" on roles/clusterroles
// 2. "escalate" on roles/clusterroles
// 3. "impersonate" on users/groups/serviceaccounts
// 4. "create" on serviceaccounts/token
// 5. Wildcard "*" on all resources and verbs
func DetectEscalationPrimitives(rules []PolicyRule) []EscalationFinding {
	var findings []EscalationFinding

	for i, r := range rules {
		hasWildcardResource := contains(r.Resources, "*")
		hasWildcardVerb := contains(r.Verbs, "*")

		if hasWildcardResource && hasWildcardVerb {
			findings = append(findings, EscalationFinding{
				RuleIndex: i,
				Primitive: "cluster-admin-wildcard",
				Details:   "contains wildcard '*' on all resources and verbs",
			})
		}

		if contains(r.Verbs, VerbBind) && (contains(r.Resources, ResourceRoles) || contains(r.Resources, ResourceClusterRoles) || hasWildcardResource) {
			findings = append(findings, EscalationFinding{
				RuleIndex: i,
				Primitive: VerbBind,
				Details:   "contains 'bind' verb permitting unauthorized role binding",
			})
		}

		if contains(r.Verbs, VerbEscalate) && (contains(r.Resources, ResourceRoles) || contains(r.Resources, ResourceClusterRoles) || hasWildcardResource) {
			findings = append(findings, EscalationFinding{
				RuleIndex: i,
				Primitive: VerbEscalate,
				Details:   "contains 'escalate' verb permitting role privilege escalation",
			})
		}

		if contains(r.Verbs, VerbImpersonate) {
			findings = append(findings, EscalationFinding{
				RuleIndex: i,
				Primitive: VerbImpersonate,
				Details:   "contains 'impersonate' verb permitting identity spoofing",
			})
		}

		for _, res := range r.Resources {
			if strings.HasSuffix(res, "token") && contains(r.Verbs, "create") {
				findings = append(findings, EscalationFinding{
					RuleIndex: i,
					Primitive: "serviceaccount-token-creation",
					Details:   "contains 'create' on serviceaccounts/token permitting credential forging",
				})
			}
		}
	}

	return findings
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}

// ApprovedIntent tracks an authorized one-time RATCHET decision for Kubernetes execution.
type ApprovedIntent struct {
	IntentID       string    `json:"intent_id"`
	TenantID       string    `json:"tenant_id"`
	RequestID      string    `json:"request_id"`
	Operation      string    `json:"operation"`
	TargetResource string    `json:"target_resource"`
	TargetSubject  string    `json:"target_subject"`
	ApprovedBy     string    `json:"approved_by"`
	ExpiresAt      time.Time `json:"expires_at"`
	Consumed       bool      `json:"consumed"`
}
