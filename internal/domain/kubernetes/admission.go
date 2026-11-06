package kubernetes

import (
	"slices"
	"strings"

	"github.com/google/uuid"
)

type UserInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid"`
	Groups   []string            `json:"groups"`
	Extra    map[string][]string `json:"extra"`
}

// Admission is normalized connector evidence, not caller-supplied authority.
// Its complete context must be authenticated before lookup, policy evaluation or
// approval correlation. AdmissionUID is assigned by Kubernetes, independently
// of the core command ID. Validation alone never authorizes target execution.
type Admission struct {
	Tenant                string   `json:"tenant_id"`
	AdmissionUID          string   `json:"admission_uid"`
	CreateUID             string   `json:"server_assigned_create_uid,omitempty"`
	User                  UserInfo `json:"user_info"`
	APIGroup              string   `json:"api_group"`
	APIVersion            string   `json:"api_version"`
	Kind                  string   `json:"kind"`
	Resource              string   `json:"resource"`
	Subresource           string   `json:"subresource"`
	Namespace             string   `json:"namespace"`
	Name                  string   `json:"name"`
	DryRun                bool     `json:"dry_run"`
	SourceResourceVersion string   `json:"source_resource_version"`
	MinGraphVersion       int64    `json:"min_graph_version"`
	ApprovedRequestID     string   `json:"approved_request_id"`
	CommandID             string   `json:"command_id"`
	Mutation              Mutation `json:"mutation"`
}

func (a Admission) Validate() error {
	if !bounded(a.CreateUID, true, 256) || a.CreateUID != "" && a.Mutation.Operation != "CREATE" {
		return ErrInvalid
	}
	if !bounded(a.Tenant, false, 128) || !bounded(a.AdmissionUID, false, 128) || !identityText(a.User.Username, false) || !bounded(a.User.UID, true, 256) || !identityValues(a.User.Groups) || len(a.User.Extra) > 32 || !bounded(a.SourceResourceVersion, false, 128) || a.MinGraphVersion < 0 || a.MinGraphVersion > 1<<53-1 || a.Mutation.Validate() != nil {
		return ErrInvalid
	}
	for key, values := range a.User.Extra {
		if !bounded(key, false, 256) || !identityValues(values) {
			return ErrInvalid
		}
	}
	if a.APIGroup != RBACGroup || a.APIVersion != "v1" || a.Subresource != "" {
		return ErrUnsupported
	}
	object := a.Mutation.After
	if object == nil {
		object = a.Mutation.Before
	}
	resources := map[string]string{"Role": "roles", "ClusterRole": "clusterroles", "RoleBinding": "rolebindings", "ClusterRoleBinding": "clusterrolebindings"}
	if object == nil || a.Kind != object.Kind || a.Resource != resources[object.Kind] || a.Namespace != object.Namespace || a.Name != object.Name {
		return ErrInvalid
	}
	if (a.ApprovedRequestID == "") != (a.CommandID == "") {
		return ErrInvalid
	}
	for _, id := range []string{a.ApprovedRequestID, a.CommandID} {
		if id != "" {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil || parsed.String() != id {
				return ErrInvalid
			}
		}
	}
	return nil
}

// PrincipalIn checks the exact observed actor and preimage against a complete
// source cut. A signed username alone cannot assert arbitrary groups or use a
// stale UID/resourceVersion. The returned principal is not a core session actor.
func (a Admission) PrincipalIn(state State) (Principal, error) {
	if err := a.Validate(); err != nil {
		return Principal{}, err
	}
	if err := state.Validate(); err != nil {
		return Principal{}, err
	}
	if a.Mutation.Cluster != state.Cluster || a.SourceResourceVersion != state.ResourceVersion {
		return Principal{}, ErrInvalid
	}
	var principal *Principal
	for _, p := range state.Principals {
		username := p.Name
		if p.Kind == "ServiceAccount" {
			username = "system:serviceaccount:" + p.Namespace + ":" + p.Name
		}
		if username == a.User.Username {
			copyPrincipal := p
			principal = &copyPrincipal
			break
		}
	}
	if principal == nil || principal.UID != a.User.UID {
		return Principal{}, ErrInvalid
	}
	if unsupportedPrincipal(*principal) || principal.Dormant {
		return Principal{}, ErrUnsupported
	}
	expected := PrincipalGroups(*principal)
	actual := slices.Clone(a.User.Groups)
	slices.Sort(actual)
	if !slices.Equal(expected, actual) {
		return Principal{}, ErrInvalid
	}
	// Extra fields are authenticated and retained, but this v1 has no verified
	// directory mapping or authorizer semantics for them. Hold instead of
	// silently treating e.g. external authorization claims as ordinary RBAC.
	if principal.CredentialID != "" {
		values := a.User.Extra["authentication.kubernetes.io/credential-id"]
		if len(a.User.Extra) != 1 || len(values) != 1 || values[0] != principal.CredentialID {
			return Principal{}, ErrUnsupported
		}
	} else if len(a.User.Extra) > 0 {
		return Principal{}, ErrUnsupported
	}
	if _, err := state.After(a.Mutation); err != nil {
		return Principal{}, err
	}
	principal.Groups = slices.Clone(principal.Groups)
	return *principal, nil
}

func unsupportedPrincipal(p Principal) bool {
	return p.Name == "system:anonymous" || slices.Contains(p.Groups, "system:unauthenticated") || (p.Kind == "User" && strings.HasPrefix(p.Name, "system:serviceaccount:"))
}
