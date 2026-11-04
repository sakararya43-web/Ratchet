package graph

import (
	"fmt"
	"maps"
	"strconv"
)

// Withdrawal rules declare their units and direction explicitly. Unknown edits
// cannot be certified as reductions. Display fields are outside this metadata.
func guardWeakened(before, after Node) (bool, error) {
	if maps.Equal(before.Properties, after.Properties) {
		return false, nil
	}
	if before.Properties["guard_kind"] != "withdrawal_threshold_v1" || after.Properties["guard_kind"] != "withdrawal_threshold_v1" {
		return false, fmt.Errorf("%w: unsupported safeguard parameter edit", ErrInvalid)
	}
	for key, value := range before.Properties {
		if key != "required_checks" && key != "threshold_usd" && key != "disabled" && after.Properties[key] != value {
			return false, ErrInvalid
		}
	}
	for key := range after.Properties {
		if key != "required_checks" && key != "threshold_usd" && key != "disabled" {
			if _, ok := before.Properties[key]; !ok {
				return false, ErrInvalid
			}
		}
	}
	a, err := guardNumber(before, "required_checks")
	if err != nil {
		return false, err
	}
	b, err := guardNumber(after, "required_checks")
	if err != nil {
		return false, err
	}
	x, err := guardNumber(before, "threshold_usd")
	if err != nil {
		return false, err
	}
	y, err := guardNumber(after, "threshold_usd")
	if err != nil {
		return false, err
	}
	return b < a || y > x || (before.Properties["disabled"] != "true" && after.Properties["disabled"] == "true"), nil
}
func guardNumber(n Node, key string) (int64, error) {
	value, err := strconv.ParseInt(n.Properties[key], 10, 64)
	if err != nil || value < 1 || value > 1<<53-1 {
		return 0, fmt.Errorf("%w: invalid safeguard value", ErrInvalid)
	}
	return value, nil
}
func (s *Snapshot) EditSafeguard(id string, parameters map[string]string) (Delta, error) {
	n, err := s.Node(id)
	if err != nil {
		return Delta{}, err
	}
	if n.Type != "Safeguard" || len(parameters) == 0 {
		return Delta{}, ErrInvalid
	}
	if n.Properties == nil {
		n.Properties = map[string]string{}
	}
	for key, value := range parameters {
		if key != "required_checks" && key != "threshold_usd" && key != "disabled" {
			return Delta{}, ErrInvalid
		}
		n.Properties[key] = value
	}
	if n.Properties["disabled"] != "" && n.Properties["disabled"] != "true" && n.Properties["disabled"] != "false" {
		return Delta{}, ErrInvalid
	}
	before, _ := s.Node(id)
	if _, err := guardWeakened(before, n); err != nil {
		return Delta{}, err
	}
	return Delta{NodesAdded: []Node{n}}, nil
}
