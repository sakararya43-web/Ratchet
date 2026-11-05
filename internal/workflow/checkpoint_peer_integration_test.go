//go:build integration && peerintegration

package workflow_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/trust"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

// This runs the unmodified peer executable from an isolated combined checkout.
// A local HTTP imitation cannot establish compatibility with its real handlers.
func TestPeerCheckpointHTTPSubmissionSigningAndRestart(t *testing.T) {
	sys := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sys.ctx = ctx
	dir := t.TempDir()
	name := "ratchet-authority"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(dir, name)
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/ratchet-authority")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual peer Authority: %v\n%s", err, output)
	}
	state := filepath.Join(dir, "authority.json")
	store, err := trust.NewStore(state)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := sys.authority.GetGenesis()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.InitGenesis(sys.tenant, genesis.ThresholdM, genesis.TotalN, genesis.Members)
	if err != nil || created.GenesisDigest != sys.root {
		t.Fatal("peer bootstrap root differs", err)
	}
	client := &http.Client{Timeout: time.Second}
	start := func() (string, func()) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		log, err := os.CreateTemp(dir, "authority-log-")
		if err != nil {
			t.Fatal(err)
		}
		process := exec.CommandContext(ctx, binary, "-port", strconv.Itoa(port), "-state", state)
		process.Stdout, process.Stderr = log, log
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = process.Process.Kill()
			_ = process.Wait()
			_ = log.Close()
		}
		t.Cleanup(stop)
		base := "http://127.0.0.1:" + strconv.Itoa(port)
		deadline := time.Now().Add(10 * time.Second)
		for {
			response, err := client.Get(base + "/healthz")
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode == 200 {
					return base, stop
				}
			}
			if time.Now().After(deadline) {
				stop()
				t.Fatal("actual peer Authority did not become healthy")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	base, stop := start()
	service, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	actor := workflow.Actor{TenantID: sys.tenant, ID: "user:sec1"}
	p, err := service.PrepareCheckpoint(ctx, actor, workflow.PrepareCheckpointInput{CommandID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := workflow.NewCheckpointAuthority(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := service.SubmitCheckpoint(ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority)
	if err != nil || len(submitted.Signatures) != 0 {
		t.Fatal("actual peer unsigned creation", err)
	}
	challenge := trust.ComputeCheckpointSigningDigest(sys.tenant, submitted.Epoch, submitted.CheckpointDigest)
	signature, err := ecdsa.SignASN1(rand.Reader, sys.authorityKey, challenge[:])
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]string{"checkpoint_id": submitted.CheckpointID, "actor_id": "authority-leader", "signature": hex.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(base+"/api/v1/authority/checkpoint/sign", "application/json", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("actual peer signing HTTP %d: %s (%v)", response.StatusCode, raw, err)
	}
	stop()
	restarted, _ := start()
	authority, err = workflow.NewCheckpointAuthority(restarted, nil)
	if err != nil {
		t.Fatal(err)
	}
	returned, err := service.SubmitCheckpoint(ctx, actor, p.Candidate.Checkpoint.CheckpointDigest, authority)
	if err != nil || len(returned.Signatures) != 1 {
		t.Fatal("actual peer restart lost or overwrote signature", err)
	}
	replacement, err := workflow.New(sys.pool, sys.store, sys.engine, sys.key, nil, []string{sys.tenant})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := replacement.AcceptCheckpoint(ctx, actor, returned)
	if err != nil || accepted.ReferenceSequence <= returned.ToSequence {
		t.Fatal("actual peer signature failed core acceptance", err)
	}
}
