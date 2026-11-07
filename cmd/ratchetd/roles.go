package main

import (
	"errors"
	"strings"
)

func selectRoles(raw string, allowed ...string) (map[string]bool, error) {
	known := map[string]bool{}
	for _, role := range allowed {
		known[role] = true
	}
	selected := map[string]bool{}
	for _, role := range strings.Split(raw, ",") {
		if !known[role] || selected[role] {
			return nil, errors.New("unknown, duplicate or empty runtime role")
		}
		selected[role] = true
	}
	return selected, nil
}
