package graph

import "slices"

func ValidateRevocationCosts(costs map[string]int64) error {
	if len(costs) == 0 || len(costs) > 4 {
		return ErrInvalid
	}
	for kind, cost := range costs {
		if cost < 1 || cost > 1_000_000_000 {
			return ErrInvalid
		}
		switch kind {
		case "ROLE_REVOKE", "REMOVE_SERVICE_PERMISSION", "TERMINATE_SESSION", "RESTRICT_ACCOUNT":
		default:
			return ErrInvalid
		}
	}
	return nil
}

// RevocationCatalog uses only authority reachable from the explicitly affected
// identities. Costs are operator configuration, never an inferred risk score.
func (s *Snapshot) RevocationCatalog(origins []string, costs map[string]int64) ([]Revocation, error) {
	if err := ValidateRevocationCosts(costs); err != nil {
		return nil, err
	}
	seen := make([]bool, len(s.nodes))
	for _, id := range origins {
		a, err := s.analyze(id)
		if err != nil {
			return nil, err
		}
		for i, v := range a.seen {
			seen[i] = seen[i] || v
		}
	}
	unique := map[string]Revocation{}
	protected := func(properties map[string]string) bool {
		return properties["protected"] == "true" || properties["removable"] == "false"
	}
	add := func(a Revocation) {
		if cost, ok := costs[a.Kind]; ok {
			a.Cost = cost
			old := unique[a.key()]
			a.Protected = a.Protected || old.Protected
			unique[a.key()] = a
		}
	}
	for i, n := range s.nodes {
		if !seen[i] {
			continue
		}
		if Identity(n.Type) {
			add(Revocation{Kind: "RESTRICT_ACCOUNT", Target: n.ID, Protected: protected(n.Properties)})
		}
		if n.Type == "Session" {
			add(Revocation{Kind: "TERMINATE_SESSION", Target: n.ID, Protected: protected(n.Properties)})
		}
	}
	for _, edge := range s.edges {
		if !seen[s.index[edge.Source]] {
			continue
		}
		source := s.nodes[s.index[edge.Source]]
		if edge.Kind == "ASSIGNED" && Identity(source.Type) && s.nodes[s.index[edge.Target]].Type == "Role" {
			add(Revocation{Kind: "ROLE_REVOKE", Target: edge.Source, Access: edge.Target, Protected: protected(edge.Properties) || protected(source.Properties)})
		}
		if edge.Kind == "GRANTS" && source.Type == "ServiceAccount" && edge.Properties["grant_id"] != "" {
			add(Revocation{Kind: "REMOVE_SERVICE_PERMISSION", Target: edge.Source, Access: edge.Properties["grant_id"], Protected: protected(edge.Properties) || protected(source.Properties)})
		}
	}
	result := []Revocation{}
	for _, a := range unique {
		result = append(result, a)
	}
	slices.SortFunc(result, func(a, b Revocation) int {
		if a.key() < b.key() {
			return -1
		}
		if a.key() > b.key() {
			return 1
		}
		return 0
	})
	return result, nil
}
