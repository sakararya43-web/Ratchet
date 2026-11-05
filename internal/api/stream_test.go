package api

import (
	"bytes"
	"testing"

	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestWatchCursorSeparatesActorsTenantsAndStreams(t *testing.T) {
	key := bytes.Repeat([]byte{4}, 32)
	actor := workflow.Actor{TenantID: "a", ID: "reviewer"}
	token := watchToken(key, actor, "changes", 27)
	if after, err := watchAfter(key, actor, "changes", token); err != nil || after != 27 {
		t.Fatalf("round trip: %d %v", after, err)
	}
	for _, test := range []struct {
		actor workflow.Actor
		kind  string
		token string
	}{
		{workflow.Actor{TenantID: "b", ID: actor.ID}, "changes", token},
		{workflow.Actor{TenantID: actor.TenantID, ID: "other"}, "changes", token},
		{actor, "incidents", token},
		{actor, "changes", token + "x"},
	} {
		if _, err := watchAfter(key, test.actor, test.kind, test.token); err == nil {
			t.Fatal("accepted mismatched or tampered cursor")
		}
	}
}
