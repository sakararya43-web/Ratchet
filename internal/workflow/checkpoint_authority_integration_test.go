//go:build integration

package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestSlowCheckpointAuthorityDoesNotHoldTenantWriteLock(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	p, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := p.Candidate.Checkpoint
	if err := sys.authority.SaveCheckpoint(&unsigned); err != nil {
		t.Fatal(err)
	}
	entered, released := make(chan struct{}), make(chan struct{})
	var first, unblock sync.Once
	release := func() { unblock.Do(func() { close(released) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Do(func() { close(entered) })
		select {
		case <-released:
		case <-r.Context().Done():
			return
		}
		if err := json.NewEncoder(w).Encode(sys.authority.ListCheckpoints()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	defer release()
	authority, err := workflow.NewCheckpointAuthority(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority)
		finished <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("submission did not reach actual HTTP request")
	}
	writeContext, cancel := context.WithTimeout(sys.ctx, 2*time.Second)
	defer cancel()
	if _, err := sys.store.Append(writeContext, eventstore.Command{TenantID: sys.tenant, ID: uuid.New(), StreamID: "evidence:while-authority-waits", ActorReference: uuid.New(), Events: []eventstore.Event{{Type: "CoreEvidenceRecorded", Facts: json.RawMessage(`{"checkpoint_waiting":true}`)}}}); err != nil {
		t.Fatal("Authority call blocked tenant append", err)
	}
	if _, err := service.SubmitCheckpoint(writeContext, actor, p.Candidate.Checkpoint.CheckpointDigest, authority); !errors.Is(err, workflow.ErrDependency) {
		t.Fatal("concurrent Authority submission bypassed delivery serialization", err)
	}
	release()
	if err := <-finished; err != nil {
		t.Fatal("original delivery failed", err)
	}
	if _, err := service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority); err != nil {
		t.Fatal("delivery lock survived completed submission", err)
	}
}

func TestCheckpointSubmissionRecoversLostAcknowledgementWithoutErasingSignatures(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	p, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	var creates atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/authority/checkpoint/list":
			if err := json.NewEncoder(w).Encode(sys.authority.ListCheckpoints()); err != nil {
				t.Error(err)
			}
		case "POST /api/v1/authority/checkpoint/create":
			creates.Add(1)
			var input struct {
				Tenant  string   `json:"tenant_id"`
				From    int64    `json:"from_sequence"`
				To      int64    `json:"to_sequence"`
				Digests []string `json:"event_digests"`
				Prior   string   `json:"prior_checkpoint_digest"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			hashes := []ports.Digest{}
			for _, raw := range input.Digests {
				digest, err := ports.DigestFromHex(raw)
				if err != nil {
					t.Error(err)
					return
				}
				hashes = append(hashes, digest)
			}
			prior, err := ports.DigestFromHex(input.Prior)
			if err != nil {
				t.Error(err)
				return
			}
			checkpoint, err := sys.authority.CreateCheckpoint(input.Tenant, input.From, input.To, hashes, prior)
			if err != nil {
				t.Error(err)
				return
			}
			if err := sys.authority.SaveCheckpoint(checkpoint); err != nil {
				t.Error(err)
				return
			}
			// The real Authority has persisted its result before the connection dies.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if err := connection.Close(); err != nil {
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
	if _, err := service.SubmitCheckpoint(sys.ctx, workflow.Actor{TenantID: sys.tenant, ID: "user:requester"}, p.Candidate.Checkpoint.CheckpointDigest, authority); !errors.Is(err, workflow.ErrPermission) {
		t.Fatal("unauthorized candidate was submitted", err)
	}
	if _, err := service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority); !errors.Is(err, workflow.ErrDependency) {
		t.Fatal("lost acknowledgement became success", err)
	}
	if creates.Load() != 1 {
		t.Fatal("candidate was not durably submitted")
	}
	signed := signCheckpoint(t, sys, p)
	if err := sys.authority.SaveCheckpoint(&signed); err != nil {
		t.Fatal(err)
	}
	recovered, err := service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority)
	if err != nil || len(recovered.Signatures) != 1 || recovered.CheckpointDigest != signed.CheckpointDigest || creates.Load() != 1 {
		t.Fatal("retry erased signatures or changed candidate", err)
	}
	if _, err := service.AcceptCheckpoint(sys.ctx, actor, recovered); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority); err != nil || creates.Load() != 1 {
		t.Fatal("accepted candidate was resubmitted", err)
	}
}

func TestCheckpointAuthorityRefusesInvalidReturnAndRedirect(t *testing.T) {
	sys := setup(t)
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	p, err := service.PrepareCheckpoint(sys.ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"changed-range", "redirect", "trailing-json"} {
		t.Run(kind, func(t *testing.T) {
			var followed atomic.Bool
			destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
			defer destination.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "redirect" {
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
					return
				}
				if kind == "trailing-json" {
					_, _ = w.Write([]byte("[] {}"))
					return
				}
				changed := p.Candidate.Checkpoint
				changed.ToSequence++
				if err := json.NewEncoder(w).Encode([]trust.AuditCheckpoint{changed}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			authority, err := workflow.NewCheckpointAuthority(server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.SubmitCheckpoint(sys.ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority)
			if err == nil || followed.Load() {
				t.Fatal("unbound Authority response or redirect accepted", err)
			}
			if kind == "changed-range" && !errors.Is(err, domain.ErrContextChanged) {
				t.Fatal(err)
			}
		})
	}
	for _, endpoint := range []string{"http://remote.test", "https://user:password@authority.test", "https://authority.test?override=1", "ftp://authority.test"} {
		if _, err := workflow.NewCheckpointAuthority(endpoint, nil); err == nil {
			t.Fatal("unsafe endpoint accepted", endpoint)
		}
	}
}
