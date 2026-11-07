// Package kubernetes defines normalized authority facts consumed by the core.
// Kubernetes API discovery, JSON decoding and admission transport belong to the
// connector; these pure operations neither contact a cluster nor authorize a write.
package kubernetes

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var ErrInvalid = errors.New("invalid normalized Kubernetes authority facts")
var ErrUnsupported = errors.New("unsupported Kubernetes authority semantics")

const RBACGroup = "rbac.authorization.k8s.io"

type Rule struct {
	APIGroups       []string `json:"api_groups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resource_names,omitempty"`
	NonResourceURLs []string `json:"non_resource_urls,omitempty"`
}

// Namespace empty means a cluster-wide binding. A namespaced binding cannot
// authorize cluster-scoped or non-resource requests, including a ClusterRole's.
type ScopedRule struct {
	Namespace string `json:"namespace"`
	Rule      Rule   `json:"rule"`
}

type Permission struct {
	APIGroup       string `json:"api_group"`
	Resource       string `json:"resource"`
	Subresource    string `json:"subresource"`
	Verb           string `json:"verb"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	NonResourceURL string `json:"non_resource_url,omitempty"`
}

func bounded(value string, empty bool, max int) bool {
	return utf8.ValidString(value) && (empty || value != "") && len(value) <= max && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func identityText(value string, empty bool) bool {
	return utf8.ValidString(value) && (empty || value != "") && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n\t")
}

func identityValues(values []string) bool {
	if len(values) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !identityText(value, false) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func valuesOK(values []string, emptyValue bool) bool {
	if len(values) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !bounded(value, emptyValue, 256) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func (r Rule) Validate() error {
	if len(r.Verbs) == 0 || !valuesOK(r.Verbs, false) || !valuesOK(r.APIGroups, true) || !valuesOK(r.Resources, false) || !identityValues(r.ResourceNames) || !valuesOK(r.NonResourceURLs, false) {
		return ErrInvalid
	}
	resource := len(r.Resources) > 0
	if resource == (len(r.NonResourceURLs) > 0) || (resource && len(r.APIGroups) == 0) {
		return ErrInvalid
	}
	if !resource && (len(r.APIGroups) != 0 || len(r.ResourceNames) != 0) {
		return ErrInvalid
	}
	for _, url := range r.NonResourceURLs {
		if url != "*" && (!strings.HasPrefix(url, "/") || strings.Contains(strings.TrimSuffix(url, "*"), "*")) {
			return ErrInvalid
		}
	}
	for _, resource := range r.Resources {
		if strings.Count(resource, "/") > 1 || strings.HasPrefix(resource, "/") || strings.HasSuffix(resource, "/") {
			return ErrInvalid
		}
	}
	return nil
}

func (p Permission) Validate() error {
	if !bounded(p.Verb, false, 128) || p.Verb == "*" || !bounded(p.Namespace, true, 253) || !identityText(p.Name, true) {
		return ErrInvalid
	}
	if p.NonResourceURL != "" {
		if !strings.HasPrefix(p.NonResourceURL, "/") || !bounded(p.NonResourceURL, false, 2048) || strings.Contains(p.NonResourceURL, "*") || p.APIGroup != "" || p.Resource != "" || p.Subresource != "" || p.Namespace != "" || p.Name != "" {
			return ErrInvalid
		}
		return nil
	}
	if !bounded(p.APIGroup, true, 256) || p.APIGroup == "*" || !bounded(p.Resource, false, 256) || !bounded(p.Subresource, true, 128) || strings.ContainsAny(p.Resource+p.Subresource, "/*") {
		return ErrInvalid
	}
	return nil
}

// Allows follows Kubernetes RBAC matching, including */subresource (not an
// arbitrary resource glob), exact resourceNames and non-resource suffix globs.
// Name constraints do not grant top-level create/deletecollection permissions.
func (s ScopedRule) Allows(p Permission) (bool, error) {
	if s.Rule.Validate() != nil || p.Validate() != nil || !bounded(s.Namespace, true, 253) {
		return false, ErrInvalid
	}
	return s.allows(p), nil
}

func matches(patterns []string, value string) bool {
	return slices.Contains(patterns, "*") || slices.Contains(patterns, value)
}

func (s ScopedRule) allows(p Permission) bool {
	r := s.Rule
	if s.Namespace != "" && s.Namespace != p.Namespace {
		return false
	}
	if !matches(r.Verbs, p.Verb) {
		return false
	}
	if p.NonResourceURL != "" {
		if s.Namespace != "" {
			return false
		}
		for _, pattern := range r.NonResourceURLs {
			if pattern == "*" || pattern == p.NonResourceURL || (strings.HasSuffix(pattern, "*") && strings.HasPrefix(p.NonResourceURL, strings.TrimSuffix(pattern, "*"))) {
				return true
			}
		}
		return false
	}
	if !matches(r.APIGroups, p.APIGroup) {
		return false
	}
	combined := p.Resource
	if p.Subresource != "" {
		combined += "/" + p.Subresource
	}
	resourceMatches := matches(r.Resources, combined) || (p.Subresource != "" && slices.Contains(r.Resources, "*/"+p.Subresource))
	if !resourceMatches {
		return false
	}
	name := p.Name
	if (p.Verb == "create" && p.Subresource == "") || p.Verb == "deletecollection" {
		name = ""
	}
	return len(r.ResourceNames) == 0 || slices.Contains(r.ResourceNames, name)
}

func Allows(rules []ScopedRule, p Permission) (bool, error) {
	if len(rules) > 16384 || p.Validate() != nil {
		return false, ErrInvalid
	}
	allowed := false
	for _, r := range rules {
		ok, err := r.Allows(p)
		if err != nil {
			return false, err
		}
		allowed = allowed || ok
	}
	return allowed, nil
}

type Subject struct {
	Kind      string `json:"kind"` // User, Group, ServiceAccount
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type SelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

type Selector struct {
	MatchLabels      map[string]string     `json:"match_labels,omitempty"`
	MatchExpressions []SelectorRequirement `json:"match_expressions,omitempty"`
}

type Object struct {
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resource_version,omitempty"`
	Rules           []Rule            `json:"rules,omitempty"`
	RoleKind        string            `json:"role_kind,omitempty"`
	RoleName        string            `json:"role_name,omitempty"`
	Subjects        []Subject         `json:"subjects,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Aggregation     []Selector        `json:"aggregation,omitempty"`
}

func (o Object) Validate() error {
	if !bounded(o.Name, false, 253) || !bounded(o.UID, true, 128) || !bounded(o.ResourceVersion, true, 128) || !bounded(o.Namespace, true, 253) || len(o.Rules) > 1024 || len(o.Subjects) > 1024 || len(o.Labels) > 128 || len(o.Aggregation) > 128 {
		return ErrInvalid
	}
	switch o.Kind {
	case "Role", "RoleBinding":
		if o.Namespace == "" {
			return ErrInvalid
		}
	case "ClusterRole", "ClusterRoleBinding":
		if o.Namespace != "" {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	role := o.Kind == "Role" || o.Kind == "ClusterRole"
	if role {
		if len(o.Subjects) != 0 || o.RoleKind != "" || o.RoleName != "" || (o.Kind == "Role" && len(o.Aggregation) != 0) {
			return ErrInvalid
		}
		for _, r := range o.Rules {
			if r.Validate() != nil || (o.Kind == "Role" && len(r.NonResourceURLs) != 0) {
				return ErrInvalid
			}
		}
	} else {
		if len(o.Rules) != 0 || len(o.Aggregation) != 0 || !bounded(o.RoleName, false, 253) || (o.RoleKind != "Role" && o.RoleKind != "ClusterRole") || (o.Kind == "ClusterRoleBinding" && o.RoleKind != "ClusterRole") {
			return ErrInvalid
		}
		for _, sub := range o.Subjects {
			if !identityText(sub.Name, false) || !bounded(sub.Namespace, true, 253) {
				return ErrInvalid
			}
			switch sub.Kind {
			case "User", "Group":
				if sub.Namespace != "" {
					return ErrInvalid
				}
			case "ServiceAccount":
				if sub.Namespace == "" {
					return ErrInvalid
				}
			default:
				return ErrUnsupported
			}
		}
	}
	for key, value := range o.Labels {
		if !bounded(key, false, 253) || !bounded(value, true, 256) {
			return ErrInvalid
		}
	}
	for _, selector := range o.Aggregation {
		if _, err := selector.Matches(nil); err != nil {
			return err
		}
	}
	return nil
}

func (s Selector) Matches(labels map[string]string) (bool, error) {
	if len(s.MatchLabels) > 128 || len(s.MatchExpressions) > 128 {
		return false, ErrInvalid
	}
	matched := true
	for key, value := range s.MatchLabels {
		if !bounded(key, false, 253) || !bounded(value, true, 256) {
			return false, ErrInvalid
		}
		actual, exists := labels[key]
		matched = matched && exists && actual == value
	}
	for _, e := range s.MatchExpressions {
		if !bounded(e.Key, false, 253) || !valuesOK(e.Values, true) {
			return false, ErrInvalid
		}
		value, exists := labels[e.Key]
		switch e.Operator {
		case "In":
			if len(e.Values) == 0 {
				return false, ErrInvalid
			}
			matched = matched && exists && slices.Contains(e.Values, value)
		case "NotIn":
			if len(e.Values) == 0 {
				return false, ErrInvalid
			}
			matched = matched && (!exists || !slices.Contains(e.Values, value))
		case "Exists":
			if len(e.Values) != 0 {
				return false, ErrInvalid
			}
			matched = matched && exists
		case "DoesNotExist":
			if len(e.Values) != 0 {
				return false, ErrInvalid
			}
			matched = matched && !exists
		default:
			return false, ErrUnsupported
		}
	}
	return matched, nil
}

// Mutation binds normalized authority semantics and the exact wire object digest.
// The connector must attest their correspondence. Resource versions are opaque;
// they are never parsed as integers or equated with a core ledger position.
type Mutation struct {
	Cluster         string       `json:"cluster_id"`
	Connector       string       `json:"connector_id"`
	Operation       string       `json:"operation"`
	Before          *Object      `json:"before,omitempty"`
	After           *Object      `json:"after,omitempty"`
	ObjectDigest    ports.Digest `json:"object_digest"`
	OldObjectDigest ports.Digest `json:"old_object_digest"`
}

func (m Mutation) Validate() error {
	if !bounded(m.Cluster, false, 128) || !bounded(m.Connector, false, 128) || m.ObjectDigest.IsZero() {
		return ErrInvalid
	}
	if m.Before != nil && (m.Before.Validate() != nil || m.Before.UID == "" || m.Before.ResourceVersion == "" || m.OldObjectDigest.IsZero()) {
		return ErrInvalid
	}
	if m.After != nil && m.After.Validate() != nil {
		return ErrInvalid
	}
	switch m.Operation {
	case "CREATE":
		if m.Before != nil || m.After == nil || m.After.UID != "" || m.After.ResourceVersion != "" || !m.OldObjectDigest.IsZero() {
			return ErrInvalid
		}
	case "UPDATE":
		if m.Before == nil || m.After == nil || m.Before.Kind != m.After.Kind || m.Before.Name != m.After.Name || m.Before.Namespace != m.After.Namespace || m.Before.UID != m.After.UID || m.Before.ResourceVersion != m.After.ResourceVersion {
			return ErrInvalid
		}
		if (m.Before.Kind == "RoleBinding" || m.Before.Kind == "ClusterRoleBinding") && (m.Before.RoleKind != m.After.RoleKind || m.Before.RoleName != m.After.RoleName) {
			return ErrInvalid
		}
	case "DELETE":
		if m.Before == nil || m.After != nil {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	return nil
}
