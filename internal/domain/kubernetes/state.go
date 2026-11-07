package kubernetes

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
)

type Principal struct {
	ID           string   `json:"identity_id"`
	UID          string   `json:"uid,omitempty"`
	Kind         string   `json:"kind"` // User or ServiceAccount
	Name         string   `json:"name"`
	Namespace    string   `json:"namespace,omitempty"`
	Groups       []string `json:"groups"`
	CredentialID string   `json:"credential_id,omitempty"`
	Dormant      bool     `json:"dormant,omitempty"`
}

type APIResource struct {
	Group      string `json:"api_group"`
	Resource   string `json:"resource"` // Includes the subresource, when present.
	Namespaced bool   `json:"namespaced"`
}

// State is a complete normalized observation, not a Kubernetes API list response.
// Complete includes the covered identity roster and verified group memberships;
// Kubernetes itself does not expose an enumerable human-user/group directory.
type State struct {
	Cluster         string        `json:"cluster_id"`
	ResourceVersion string        `json:"resource_version"`
	Complete        bool          `json:"complete"`
	Namespaces      []string      `json:"namespaces"`
	Principals      []Principal   `json:"principals"`
	Resources       []APIResource `json:"resources"`
	Objects         []Object      `json:"objects"`
	proposed        bool
}

func ObjectKey(o Object) string { return o.Kind + "/" + o.Namespace + "/" + o.Name }

func (s State) Clone() (State, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return State{}, err
	}
	var out State
	if err := json.Unmarshal(raw, &out); err != nil {
		return State{}, err
	}
	out.proposed = s.proposed
	return out, nil
}

func (s State) ValidateObserved() error {
	if s.proposed {
		return ErrInvalid
	}
	return s.Validate()
}

func (s State) Validate() error {
	if !s.Complete || !bounded(s.Cluster, false, 128) || !bounded(s.ResourceVersion, false, 128) || len(s.Namespaces) > 128 || len(s.Principals) > 1024 || len(s.Objects) > 4096 || len(s.Resources) > 2048 || !valuesOK(s.Namespaces, false) {
		return ErrInvalid
	}
	ids, names, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range s.Principals {
		if !bounded(p.ID, false, 256) || !bounded(p.UID, true, 256) || !bounded(p.CredentialID, true, 256) || (p.Dormant && (p.Kind != "ServiceAccount" || p.UID != "")) || !identityText(p.Name, false) || !identityValues(p.Groups) || ids[p.ID] || names[PrincipalKey(p.Kind, p.Namespace, p.Name)] {
			return ErrInvalid
		}
		if p.Kind != "User" && p.Kind != "ServiceAccount" {
			return ErrUnsupported
		}
		anonymous := p.Kind == "User" && p.Name == "system:anonymous" && p.UID == "" && len(p.Groups) == 1 && p.Groups[0] == "system:unauthenticated"
		if unsupportedPrincipal(p) && !anonymous {
			return ErrUnsupported
		}
		if (p.Kind == "User" && p.Namespace != "") || (p.Kind == "ServiceAccount" && !slices.Contains(s.Namespaces, p.Namespace)) {
			return ErrInvalid
		}
		ids[p.ID], names[PrincipalKey(p.Kind, p.Namespace, p.Name)] = true, true
	}
	for _, resource := range s.Resources {
		key := resource.Group + "/" + resource.Resource
		if !bounded(resource.Group, true, 256) || !bounded(resource.Resource, false, 256) || strings.Contains(resource.Group, "*") || strings.Contains(resource.Resource, "*") || keys[key] {
			return ErrInvalid
		}
		keys[key] = true
	}
	keys = map[string]bool{}
	uids := map[string]bool{}
	for _, object := range s.Objects {
		if object.Validate() != nil || keys[ObjectKey(object)] || (!s.proposed && (object.UID == "" || object.ResourceVersion == "")) || (object.Namespace != "" && !slices.Contains(s.Namespaces, object.Namespace)) {
			return ErrInvalid
		}
		if object.UID != "" {
			if uids[object.UID] {
				return ErrInvalid
			}
			uids[object.UID] = true
		}
		keys[ObjectKey(object)] = true
	}
	for _, binding := range s.Objects {
		if binding.Kind != "RoleBinding" && binding.Kind != "ClusterRoleBinding" {
			continue
		}
		// A real Kubernetes binding can outlive its referenced role. It grants
		// no permissions while that definition is absent; creating that role
		// later must be assessed for all of the existing binding's subjects.
		for _, subject := range binding.Subjects {
			if subject.Kind != "Group" && !names[PrincipalKey(subject.Kind, subject.Namespace, subject.Name)] {
				return ErrInvalid
			}
		}
	}
	return nil
}

func PrincipalKey(kind, namespace, name string) string { return kind + "/" + namespace + "/" + name }

func SubjectKey(s Subject) string { return PrincipalKey(s.Kind, s.Namespace, s.Name) }

func PrincipalGroups(p Principal) []string {
	groups := append([]string(nil), p.Groups...)
	if p.Kind == "User" && p.Name == "system:anonymous" {
		groups = append(groups, "system:unauthenticated")
	} else {
		groups = append(groups, "system:authenticated")
	}
	if p.Kind == "ServiceAccount" {
		groups = append(groups, "system:serviceaccounts", "system:serviceaccounts:"+p.Namespace)
	}
	slices.Sort(groups)
	return slices.Compact(groups)
}

func SubjectMatches(p Principal, subject Subject) bool {
	if subject.Kind == "Group" {
		return slices.Contains(PrincipalGroups(p), subject.Name)
	}
	return p.Kind == subject.Kind && p.Name == subject.Name && p.Namespace == subject.Namespace
}

// RoleRules resolves aggregation with a least fixed point over the observed
// selector graph. Cycles cannot invent rules, and missing labels do not match In.
func (s State) RoleRules() (map[string][]Rule, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	roles := map[string]Object{}
	sets := map[string]map[string]Rule{}
	for _, object := range s.Objects {
		if object.Kind != "Role" && object.Kind != "ClusterRole" {
			continue
		}
		key := ObjectKey(object)
		roles[key] = object
		sets[key] = map[string]Rule{}
		// Aggregated roles' observed rules can temporarily lag selectors. Include
		// both observed authority and selected authority; never erase live grants.
		for _, rule := range object.Rules {
			raw, _ := json.Marshal(rule)
			sets[key][string(raw)] = rule
		}
	}
	roleKeys := slices.Sorted(maps.Keys(roles))
	work := 0
	for pass := 0; pass <= len(roles); pass++ {
		changed := false
		for _, key := range roleKeys {
			object := roles[key]
			for _, selector := range object.Aggregation {
				for _, candidateKey := range roleKeys {
					candidate := roles[candidateKey]
					work++
					if work > 2_000_000 {
						return nil, ErrUnsupported
					}
					if candidate.Kind != "ClusterRole" || candidateKey == key {
						continue
					}
					match, err := selector.Matches(candidate.Labels)
					if err != nil {
						return nil, err
					}
					if !match {
						continue
					}
					for signature, rule := range sets[candidateKey] {
						work++
						if work > 2_000_000 {
							return nil, ErrUnsupported
						}
						if _, exists := sets[key][signature]; !exists {
							sets[key][signature] = rule
							changed = true
						}
					}
				}
			}
		}
		if !changed {
			out := map[string][]Rule{}
			for key, set := range sets {
				signatures := make([]string, 0, len(set))
				for signature := range set {
					signatures = append(signatures, signature)
				}
				slices.Sort(signatures)
				for _, signature := range signatures {
					r := set[signature]
					r.APIGroups = slices.Clone(r.APIGroups)
					r.Resources = slices.Clone(r.Resources)
					r.Verbs = slices.Clone(r.Verbs)
					r.ResourceNames = slices.Clone(r.ResourceNames)
					r.NonResourceURLs = slices.Clone(r.NonResourceURLs)
					out[key] = append(out[key], r)
				}
			}
			return out, nil
		}
		if pass == len(roles) {
			return nil, ErrInvalid
		}
	}
	return nil, ErrInvalid
}

func (s State) EffectiveRules(identity string) ([]ScopedRule, error) {
	roles, err := s.RoleRules()
	if err != nil {
		return nil, err
	}
	var principal *Principal
	for i := range s.Principals {
		if s.Principals[i].ID == identity {
			principal = &s.Principals[i]
			break
		}
	}
	if principal == nil {
		return nil, ErrInvalid
	}
	if slices.Contains(PrincipalGroups(*principal), "system:masters") {
		return []ScopedRule{{Rule: Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, {Rule: Rule{Verbs: []string{"*"}, NonResourceURLs: []string{"*"}}}}, nil
	}
	out := []ScopedRule{}
	for _, binding := range s.Objects {
		if binding.Kind != "RoleBinding" && binding.Kind != "ClusterRoleBinding" {
			continue
		}
		matched := false
		for _, subject := range binding.Subjects {
			matched = matched || SubjectMatches(*principal, subject)
		}
		if !matched {
			continue
		}
		role := Object{Kind: binding.RoleKind, Name: binding.RoleName}
		if role.Kind == "Role" {
			role.Namespace = binding.Namespace
		}
		for _, rule := range roles[ObjectKey(role)] {
			out = append(out, ScopedRule{Namespace: binding.Namespace, Rule: rule})
		}
	}
	return out, nil
}

// After verifies the exact observed preimage before making an isolated proposal.
// A DELETE is not assumed to be a reduction; callers must compare consequences,
// including controllers, aggregate selectors and the current source context.
func (s State) After(m Mutation) (State, error) {
	if s.Validate() != nil || m.Validate() != nil || m.Cluster != s.Cluster {
		return State{}, ErrInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return State{}, err
	}
	var out State
	if json.Unmarshal(raw, &out) != nil {
		return State{}, ErrInvalid
	}
	target := m.After
	if target == nil {
		target = m.Before
	}
	index := -1
	for i, o := range out.Objects {
		if ObjectKey(o) == ObjectKey(*target) {
			index = i
			break
		}
	}
	if m.Operation == "CREATE" {
		if index >= 0 {
			return State{}, ErrInvalid
		}
		out.Objects = append(out.Objects, *m.After)
	} else {
		if index < 0 {
			return State{}, ErrInvalid
		}
		actual, _ := json.Marshal(out.Objects[index])
		expected, _ := json.Marshal(m.Before)
		if string(actual) != string(expected) {
			return State{}, ErrInvalid
		}
		if m.After == nil {
			out.Objects = slices.Delete(out.Objects, index, index+1)
		} else {
			out.Objects[index] = *m.After
		}
	}
	out.proposed = true
	// Deep-copy caller-owned additions as well as the original state.
	raw, err = json.Marshal(out)
	if err != nil {
		return State{}, err
	}
	var detached State
	if json.Unmarshal(raw, &detached) != nil {
		return State{}, ErrInvalid
	}
	detached.proposed = true
	out = detached
	if err := out.Validate(); err != nil {
		return State{}, err
	}
	return out, nil
}
