package eventstore

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestRejectsUnsafeCanonicalFactsAndPersonalData(t *testing.T) {
	for _, facts := range []string{`{"revision":9007199254740993}`, `{"revision":-9007199254740993}`, `{"revision":1e30}`, `{"nested":{"justification":"personal"}}`, `{"items":[{"email":"private@example.org"}]}`, `null`, `[]`} {
		cmd := Command{TenantID: "exchange", ID: uuid.New(), ActorReference: uuid.New(), StreamID: "evidence:validation", Events: []Event{{Type: "EvidenceRecorded", Facts: json.RawMessage(facts)}}}
		if err := validate(cmd); err == nil {
			t.Fatalf("accepted unsafe facts %s", facts)
		}
	}
}
