package main

import "testing"

func TestRuntimeRoleSelectionRejectsAmbiguity(t *testing.T) {
	for _, raw := range []string{"", "api,api", "worker,unknown", "api,", "worker, api"} {
		if _, err := selectRoles(raw, "api", "worker", "relay"); err == nil {
			t.Fatal("ambiguous roles accepted", raw)
		}
	}
	for _, raw := range []string{"api", "worker", "relay", "api,worker,relay"} {
		roles, err := selectRoles(raw, "api", "worker", "relay")
		if err != nil || len(roles) == 0 {
			t.Fatal("supported role refused", raw, err)
		}
	}
}
