package k8s

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

func TestStagingAuthenticatesCoreAndPersistsExactCommandAcrossRestart(t *testing.T) {
	corePublic, core, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, connector, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := AdmissionConfig{Adapter: &K8sAdapter{config: AdapterConfig{Tenant: "tenant", Connector: "native", Cluster: "kind", StateDirectory: t.TempDir()}}, CoreURL: "https://core.test", CorePublicKey: corePublic, SigningKey: connector, StorageKey: bytes.Repeat([]byte{1}, 32), HTTPClient: &http.Client{}, Results: func(context.Context, string, []byte) error { return errors.New("transport deliberately unavailable") }}
	h, err := NewNativeAdmissionHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	plan := ports.Digest{1}
	command := workflow.PreparedCommand{SchemaVersion: 1, Tenant: "tenant", Connector: "native", CommandID: uuid.NewString(), RequestID: uuid.NewString(), Purpose: "KUBERNETES_ADMISSION", Deadline: time.Now().Add(time.Minute), Kubernetes: &workflow.NativeCommandBinding{PlanDigest: plan}, Envelope: &domain.Envelope{Intent: domain.Intent{Kind: "K8S_RBAC_CHANGE", Kubernetes: &domain.KubernetesChange{PlanDigest: plan}}}}
	command.EnvelopeDigest, err = canon.New().Digest(command.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := commandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	command.Signature = ed25519.Sign(core, digest[:])
	if err := h.Stage(t.Context(), command); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNativeAdmissionHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Stage(t.Context(), command); err != nil {
		t.Fatal("duplicate after restart", err)
	}
	changed := command
	changed.RequestID = uuid.NewString()
	if err := restarted.Stage(t.Context(), changed); !errors.Is(err, bus.ErrAuthentication) {
		t.Fatal("tampered signed command accepted", err)
	}
	changed = command
	changed.Connector = "other"
	digest, err = commandDigest(changed)
	if err != nil {
		t.Fatal(err)
	}
	changed.Signature = ed25519.Sign(core, digest[:])
	if err := restarted.Stage(t.Context(), changed); err == nil {
		t.Fatal("cross-connector command accepted")
	}
	pending := pendingAdmission{Status: "PREPARED", Command: command, Admission: kube.Admission{User: kube.UserInfo{Username: "Private Native User"}}}
	if err := h.savePending(pending); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(h.pendingPath(command.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Private Native User")) {
		t.Fatal("raw admission stored in plaintext")
	}
	got, err := restarted.loadPending(command.CommandID)
	if err != nil || got.Admission.User.Username != "Private Native User" {
		t.Fatal("encrypted context not restartable", err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(h.pendingPath(command.CommandID), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.loadPending(command.CommandID); err == nil {
		t.Fatal("corrupt durable context accepted")
	}
}

func TestWebhookRequiresAuthenticatedAPIServerBeforeParsingUserInfo(t *testing.T) {
	h := NewAdmissionWebhookHandler().HTTPHandler()
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://webhook.test/validate", bytes.NewBufferString(`{"userInfo":{"username":"admin"}}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatal("unverified caller reached admission", response.Code)
	}
}

func TestRuntimeRejectsUnknownOptionsAndRelativeSecretPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	for _, raw := range []string{`{"insecure_skip_verify":true}`, `{"kubeconfig":"relative"}`, `{} {}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRuntimeConfig(path); err == nil {
			t.Fatal("unsafe runtime configuration accepted", raw)
		}
	}
}
