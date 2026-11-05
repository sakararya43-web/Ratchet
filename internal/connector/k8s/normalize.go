package k8s

import (
	"encoding/json"
	"errors"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type apiMetadata struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []json.RawMessage `json:"ownerReferences"`
	Finalizers        []string          `json:"finalizers"`
	DeletionTimestamp string            `json:"deletionTimestamp"`
}
type apiObject struct {
	APIVersion      string       `json:"apiVersion"`
	Kind            string       `json:"kind"`
	Metadata        apiMetadata  `json:"metadata"`
	Rules           []PolicyRule `json:"rules"`
	RoleRef         RoleRef      `json:"roleRef"`
	Subjects        []Subject    `json:"subjects"`
	AggregationRule struct {
		Selectors []struct {
			Labels      map[string]string `json:"matchLabels"`
			Expressions []struct {
				Key, Operator string
				Values        []string
			} `json:"matchExpressions"`
		} `json:"clusterRoleSelectors"`
	} `json:"aggregationRule"`
}

// NormalizeObject preserves the complete RBAC security specification. Unmodeled
// ownership/finalizer deletion effects are refused rather than guessed safe.
func NormalizeObject(raw map[string]any) (kube.Object, ports.Digest, error) {
	var out kube.Object
	encoded, err := json.Marshal(raw)
	if err != nil {
		return out, ports.Digest{}, err
	}
	var o apiObject
	if json.Unmarshal(encoded, &o) != nil || o.APIVersion != "rbac.authorization.k8s.io/v1" {
		return out, ports.Digest{}, kube.ErrUnsupported
	}
	for key := range raw {
		switch key {
		case "apiVersion", "kind", "metadata", "rules", "roleRef", "subjects", "aggregationRule":
		default:
			return out, ports.Digest{}, kube.ErrUnsupported
		}
	}
	if len(o.Metadata.OwnerReferences) != 0 || len(o.Metadata.Finalizers) != 0 || o.Metadata.DeletionTimestamp != "" {
		return out, ports.Digest{}, kube.ErrUnsupported
	}
	out = kube.Object{Kind: o.Kind, Name: o.Metadata.Name, Namespace: o.Metadata.Namespace, UID: o.Metadata.UID, ResourceVersion: o.Metadata.ResourceVersion, Labels: o.Metadata.Labels, RoleKind: o.RoleRef.Kind, RoleName: o.RoleRef.Name}
	if o.RoleRef.Kind != "" && o.RoleRef.APIGroup != kube.RBACGroup {
		return out, ports.Digest{}, kube.ErrInvalid
	}
	for _, r := range o.Rules {
		out.Rules = append(out.Rules, kube.Rule{APIGroups: r.APIGroups, Resources: r.Resources, Verbs: r.Verbs, ResourceNames: r.ResourceNames, NonResourceURLs: r.NonResourceURLs})
	}
	for _, s := range o.Subjects {
		out.Subjects = append(out.Subjects, kube.Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
	}
	for _, selector := range o.AggregationRule.Selectors {
		s := kube.Selector{MatchLabels: selector.Labels}
		for _, e := range selector.Expressions {
			s.MatchExpressions = append(s.MatchExpressions, kube.SelectorRequirement{Key: e.Key, Operator: e.Operator, Values: e.Values})
		}
		out.Aggregation = append(out.Aggregation, s)
	}
	if err := out.Validate(); err != nil {
		return out, ports.Digest{}, err
	}
	// These fields are server-maintained bookkeeping, not submitted authority.
	// Every remaining raw field (including annotations and labels) is committed.
	var canonical map[string]any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		return out, ports.Digest{}, err
	}
	if metadata, ok := canonical["metadata"].(map[string]any); ok {
		for _, key := range []string{"creationTimestamp", "managedFields", "generation"} {
			delete(metadata, key)
		}
	}
	digest, err := canon.New().Digest(canonical)
	return out, digest, err
}

func NormalizeAdmission(tenant, connector, cluster, source string, request *AdmissionRequest) (kube.Admission, error) {
	if request == nil {
		return kube.Admission{}, kube.ErrInvalid
	}
	mutation := kube.Mutation{Connector: connector, Cluster: cluster, Operation: request.Operation}
	if request.Object != nil {
		o, digest, err := NormalizeObject(request.Object)
		if err != nil {
			return kube.Admission{}, err
		}
		mutation.After, mutation.ObjectDigest = &o, digest
	}
	if request.OldObject != nil {
		o, digest, err := NormalizeObject(request.OldObject)
		if err != nil {
			return kube.Admission{}, err
		}
		mutation.Before, mutation.OldObjectDigest = &o, digest
		if request.Operation == "DELETE" {
			mutation.ObjectDigest = digest
		}
	}
	if request.Operation == "DELETE" {
		preconditions, ok := request.Options["preconditions"].(map[string]any)
		if !ok || mutation.Before == nil || preconditions["uid"] != mutation.Before.UID || preconditions["resourceVersion"] != mutation.Before.ResourceVersion {
			return kube.Admission{}, errors.New("DELETE requires exact UID/resourceVersion preconditions")
		}
	}
	info, err := json.Marshal(request.UserInfo)
	if err != nil {
		return kube.Admission{}, err
	}
	var user kube.UserInfo
	if err := json.Unmarshal(info, &user); err != nil {
		return kube.Admission{}, err
	}
	// Kubernetes uses camel-case UserInfo keys, while the normalized fields are
	// username/uid/groups/extra and therefore retain their exact native values.
	a := kube.Admission{Tenant: tenant, AdmissionUID: request.UID, User: user, APIGroup: request.Kind["group"], APIVersion: request.Kind["version"], Kind: request.Kind["kind"], Resource: request.Resource["resource"], Subresource: request.SubResource, Name: request.Name, Namespace: request.Namespace, DryRun: request.DryRun, SourceResourceVersion: source, Mutation: mutation}
	if request.Resource["group"] != a.APIGroup || request.Resource["version"] != a.APIVersion {
		return kube.Admission{}, kube.ErrInvalid
	}
	return a, a.Validate()
}
