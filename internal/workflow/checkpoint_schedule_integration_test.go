//go:build integration

package workflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestCheckpointScheduleSurvivesRestartReusesPendingCandidateAndAdvancesAfterAcceptance(t *testing.T) {
	sys := setup(t)
	config := workflow.Config{CheckpointSchedules: map[string]workflow.CheckpointSchedule{sys.tenant: {Actor: "user:sec1", Interval: time.Minute}}}
	makeService := func() *workflow.Service {
		s, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, config)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	stop := func(s *workflow.Service) {
		ctx, cancel := context.WithTimeout(sys.ctx, 5*time.Second)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var due time.Time
	var count int
	read := func() error {
		return sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
			if err := tx.QueryRow(sys.ctx, `SELECT next_run_at FROM ratchet.checkpoint_schedules WHERE tenant_id=$1`, sys.tenant).Scan(&due); err != nil {
				return err
			}
			return tx.QueryRow(sys.ctx, `SELECT count(*) FROM ratchet.checkpoint_candidates WHERE tenant_id=$1`, sys.tenant).Scan(&count)
		})
	}
	wait := func(previous time.Time, candidates int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			if err := read(); err != nil {
				t.Fatal(err)
			}
			if due.After(previous) && count == candidates {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("schedule did not advance: %v %d", due, count)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	setOverdue := func() time.Time {
		var at time.Time
		if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, now time.Time) error {
			at = now.Add(-5 * time.Minute)
			_, err := tx.Exec(sys.ctx, `UPDATE ratchet.checkpoint_schedules SET next_run_at=$2 WHERE tenant_id=$1`, sys.tenant, at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return at
	}
	first := makeService()
	if err := first.Start(sys.ctx); err != nil {
		t.Fatal(err)
	}
	wait(time.Now(), 1)
	stop(first)
	missed := setOverdue()
	replacement := makeService()
	if err := replacement.Start(sys.ctx); err != nil {
		t.Fatal(err)
	}
	wait(missed, 1)
	stop(replacement)
	if !due.After(time.Now()) {
		t.Fatal("missed intervals were replayed as a burst")
	}

	// Duplicate startup/tick delivery must not create another unsigned root.
	before := due
	if err := replacement.TickCheckpoint(sys.ctx, workflow.CheckpointTickArgs{Tenant: sys.tenant, Due: due}); err == nil {
		t.Fatal("early tick ignored the database deadline")
	}
	if err := read(); err != nil || !due.Equal(before) || count != 1 {
		t.Fatal("early tick changed state", err)
	}
	var proposal workflow.CheckpointProposal
	// The schedule's candidate is available to the normal authenticated audit API.
	var commandID string
	if err := sys.store.WithTenantTx(sys.ctx, sys.tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(sys.ctx, `SELECT command_id::text FROM ratchet.checkpoint_candidates WHERE tenant_id=$1`, sys.tenant).Scan(&commandID)
	}); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(commandID)
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	proposal, err = replacement.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: id})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.AcceptCheckpoint(sys.ctx, actor, signCheckpoint(t, sys, proposal)); err != nil {
		t.Fatal(err)
	}
	missed = setOverdue()
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errorsSeen <- replacement.TickCheckpoint(sys.ctx, workflow.CheckpointTickArgs{Tenant: sys.tenant, Due: missed})
		}()
	}
	wg.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := read(); err != nil || count != 2 || !due.After(time.Now()) {
		t.Fatal("accepted checkpoint did not advance to one new root", count, err)
	}
	if err := replacement.TickCheckpoint(sys.ctx, workflow.CheckpointTickArgs{Tenant: sys.tenant, Due: missed}); err != nil {
		t.Fatal("stale job failed instead of becoming a no-op", err)
	}
	config.CheckpointSchedules[sys.tenant] = workflow.CheckpointSchedule{Actor: "user:requester", Interval: time.Minute}
	denied := makeService()
	missed = setOverdue()
	if err := denied.TickCheckpoint(sys.ctx, workflow.CheckpointTickArgs{Tenant: sys.tenant, Due: missed}); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("scheduler bypassed current actor authorization", err)
	}
	if err := read(); err != nil || !due.Equal(missed) || count != 2 {
		t.Fatal("failed tick advanced its durable slot", err)
	}
}

func TestScheduledCheckpointDeliveryWaitsForRealMemberSignaturesAndRecovers(t *testing.T) {
	sys := setup(t)
	var creates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/authority/checkpoint/list":
			if err := json.NewEncoder(w).Encode(sys.authority.ListCheckpoints()); err != nil {
				t.Error(err)
			}
		case "POST /api/v1/authority/checkpoint/create":
			var input struct {
				Tenant string   `json:"tenant_id"`
				From   int64    `json:"from_sequence"`
				To     int64    `json:"to_sequence"`
				Hashes []string `json:"event_digests"`
				Prior  string   `json:"prior_checkpoint_digest"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			hashes := make([]ports.Digest, len(input.Hashes))
			for i, value := range input.Hashes {
				d, err := ports.DigestFromHex(value)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				hashes[i] = d
			}
			prior, err := ports.DigestFromHex(input.Prior)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			checkpoint, err := sys.authority.CreateCheckpoint(input.Tenant, input.From, input.To, hashes, prior)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if err := sys.authority.SaveCheckpoint(checkpoint); err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			creates.Add(1)
			if err := json.NewEncoder(w).Encode(checkpoint); err != nil {
				t.Error(err)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	authority, err := workflow.NewCheckpointAuthority(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := workflow.Config{CheckpointSchedules: map[string]workflow.CheckpointSchedule{sys.tenant: {Actor: "user:sec1", Interval: time.Hour, Authority: authority}}}
	first, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(sys.ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for creates.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("durable scheduler did not submit candidate")
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop, cancel := context.WithTimeout(sys.ctx, 5*time.Second)
	defer cancel()
	if err := first.Stop(stop); err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	history, _, err := first.Checkpoints(sys.ctx, actor, 0, 0, 10)
	if err != nil || len(history) != 0 {
		t.Fatal("unsigned Authority response became accepted", err)
	}
	checkpoints := sys.authority.ListCheckpoints()
	if len(checkpoints) != 1 {
		t.Fatal("multiple pending roots")
	}
	signed := *checkpoints[0]
	digest := trust.ComputeCheckpointSigningDigest(sys.tenant, signed.Epoch, signed.CheckpointDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SignCheckpoint(&signed, trust.MemberSignature{ActorID: "authority-leader", Signature: signature}); err != nil {
		t.Fatal(err)
	}
	if err := sys.authority.SaveCheckpoint(&signed); err != nil {
		t.Fatal(err)
	}
	replacement, err := workflow.NewConfigured(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant}, config)
	if err != nil {
		t.Fatal(err)
	}
	args := workflow.CheckpointDeliveryArgs{Tenant: sys.tenant, Digest: signed.CheckpointDigest}
	for range 2 {
		if err := replacement.DeliverCheckpoint(sys.ctx, args); err != nil {
			t.Fatal(err)
		}
	}
	history, _, err = replacement.Checkpoints(sys.ctx, actor, 0, 0, 10)
	if err != nil || len(history) != 1 || creates.Load() != 1 || history[0].Evidence.Signed.CheckpointDigest != signed.CheckpointDigest {
		t.Fatal("replacement delivery lost signatures or duplicated acceptance", len(history), creates.Load(), err)
	}
}
