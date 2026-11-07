package domain

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCommandCASDurableReceiptAndFailedPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	command := TargetCommand{CommandID: "original", TenantID: store.GetState().TenantID, Action: "ASSIGN_ROLE", TargetIdentity: "user:rahul", ResourceOrRole: "role:exchange-admin", ExpectedTargetRevision: 1000}
	receipt, err := store.Execute(command)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := restarted.Execute(command)
	if err != nil || duplicate.Revision != receipt.Revision || !duplicate.AppliedAt.Equal(receipt.AppliedAt) {
		t.Fatal("durable duplicate changed receipt", err)
	}
	altered := command
	altered.ResourceOrRole = "role:finance-analyst"
	if _, err = restarted.Execute(altered); err == nil {
		t.Fatal("reused identity with changed intent accepted")
	}
	before := restarted.GetState().Revision
	next := command
	next.CommandID = "failed-write"
	next.Action = "REVOKE_ROLE"
	next.ExpectedTargetRevision = before
	if err = os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Execute(next); err == nil {
		t.Fatal("failed persistence acknowledged")
	}
	if restarted.GetState().Revision != before {
		t.Fatal("failed persistence changed visible IAM")
	}
}
func TestCompetingCommandsUseSingleTargetCAS(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := TargetCommand{CommandID: "a", TenantID: store.GetState().TenantID, Action: "ASSIGN_ROLE", TargetIdentity: "user:rahul", ResourceOrRole: "role:exchange-admin", ExpectedTargetRevision: 1000}
	other := base
	other.CommandID = "b"
	other.TargetIdentity = "user:intern"
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, c := range []TargetCommand{base, other} {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := store.Execute(c); results <- err }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		}
	}
	if accepted != 1 || store.GetState().Revision != 1001 {
		t.Fatal("competing stale commands both applied", accepted)
	}
}
