package k8s

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/workflow"
)

// RuntimeConfig contains paths, never inline secret keys. DirectoryFile is an
// operator-attested complete identity/group roster for this selected cluster.
type RuntimeConfig struct {
	Tenant            string `json:"tenant_id"`
	Connector         string `json:"connector_id"`
	Cluster           string `json:"cluster_id"`
	Kubeconfig        string `json:"kubeconfig"`
	Context           string `json:"context"`
	StateDirectory    string `json:"state_directory"`
	DirectoryFile     string `json:"directory_file"`
	Listen            string `json:"listen"`
	ServerCertificate string `json:"server_certificate"`
	ServerKey         string `json:"server_key"`
	APIServerClientCA string `json:"api_server_client_ca"`
	CoreURL           string `json:"core_url"`
	CoreCA            string `json:"core_ca"`
	CorePublicKey     string `json:"core_public_key"`
	SigningKey        string `json:"signing_key"`
	StorageKey        string `json:"storage_key"`
	NATSURL           string `json:"nats_url"`
	NATSCredentials   string `json:"nats_credentials"`
	CapabilityFile    string `json:"capability_file"`
}

func ReadRuntimeConfig(path string) (RuntimeConfig, error) {
	var c RuntimeConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if len(raw) > 1<<20 {
		return c, kube.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, kube.ErrInvalid
	}
	for _, p := range []string{c.Kubeconfig, c.StateDirectory, c.DirectoryFile, c.ServerCertificate, c.ServerKey, c.APIServerClientCA, c.CoreCA, c.CorePublicKey, c.SigningKey, c.StorageKey, c.CapabilityFile} {
		if !filepath.IsAbs(p) {
			return c, errors.New("runtime file paths must be absolute")
		}
	}
	if c.Listen == "" || c.NATSURL == "" {
		return c, kube.ErrInvalid
	}
	return c, nil
}

func keyFile(path string, size int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid configured hexadecimal key file")
	}
	return decoded, nil
}

func certPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("configured certificate authority is invalid")
	}
	return pool, nil
}

// Run serves only the native signed admission protocol. It never writes RBAC
// objects: the API server performs the one authorized request, and reconciliation
// independently reads it. All command/result queues survive process restart.
func Run(ctx context.Context, c RuntimeConfig, logger *slog.Logger) error {
	if logger == nil {
		return kube.ErrInvalid
	}
	var directory struct {
		Complete   bool             `json:"complete"`
		Principals []kube.Principal `json:"principals"`
	}
	raw, err := os.ReadFile(c.DirectoryFile)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return kube.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&directory) != nil || d.Decode(new(any)) != io.EOF || !directory.Complete {
		return errors.New("complete attested identity directory required")
	}
	a, err := NewConfiguredAdapter(AdapterConfig{Tenant: c.Tenant, Connector: c.Connector, Cluster: c.Cluster, Kubeconfig: c.Kubeconfig, Context: c.Context, StateDirectory: c.StateDirectory, Directory: directory.Principals, DirectoryComplete: true})
	if err != nil {
		return err
	}
	private, err := keyFile(c.SigningKey, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}
	public, err := keyFile(c.CorePublicKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	storage, err := keyFile(c.StorageKey, 32)
	if err != nil {
		return err
	}
	serverCA, err := certPool(c.APIServerClientCA)
	if err != nil {
		return err
	}
	coreCA, err := certPool(c.CoreCA)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(c.ServerCertificate, c.ServerKey)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: coreCA, MinVersion: tls.VersionTLS13}, MaxIdleConns: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := []nats.Option{}
	if c.NATSCredentials != "" {
		options = append(options, nats.UserCredentials(c.NATSCredentials))
	}
	broker, err := bus.Connect(c.NATSURL, options...)
	if err != nil {
		return err
	}
	defer broker.Close()
	if err := broker.EnsureTenant(ctx, c.Tenant); err != nil {
		return err
	}
	if err := broker.EnsureExecution(ctx, c.Tenant, c.Connector); err != nil {
		return err
	}
	h, err := NewNativeAdmissionHandler(AdmissionConfig{Adapter: a, CoreURL: c.CoreURL, CorePublicKey: public, SigningKey: private, StorageKey: storage, HTTPClient: client, Results: func(ctx context.Context, id string, payload []byte) error {
		return broker.Publish(ctx, "ratchet."+c.Tenant+".exec.results", id, payload)
	}})
	if err != nil {
		return err
	}
	if err := a.PublishSnapshot(ctx, private, broker.Publish); err != nil {
		return err
	}
	// Capability is signed only after real API inventory, writable durable state,
	// authenticated configuration and durable broker streams have passed preflight.
	capability := workflow.Capability{Tenant: c.Tenant, Connector: c.Connector, Protocol: "RATCHET_EXEC_V1", Expires: time.Now().UTC().Add(time.Hour), BoundCommands: true, AtomicPreconditions: true, DurableDedup: true, IndependentReadBack: true, NativeRBAC: true}
	digest, err := canon.New().Digest(struct {
		Domain string `json:"domain"`
		Body   any    `json:"body"`
	}{"RATCHET_EXEC_CAPABILITY_V1", capability})
	if err != nil {
		return err
	}
	capability.Signature = ed25519.Sign(private, digest[:])
	raw, err = json.Marshal(capability)
	if err != nil {
		return err
	}
	if err := atomicFile(c.CapabilityFile, raw); err != nil {
		return err
	}
	var lastSync atomic.Int64
	lastSync.Store(time.Now().UnixNano())
	mux := http.NewServeMux()
	mux.Handle("/validate", h.HTTPHandler())
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		probe, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if time.Since(time.Unix(0, lastSync.Load())) > 45*time.Second || broker.Ready(probe) != nil {
			http.Error(w, "native dependency unavailable", http.StatusServiceUnavailable)
			return
		}
		request, err := http.NewRequestWithContext(probe, http.MethodGet, strings.TrimRight(c.CoreURL, "/")+"/readyz", nil)
		if err != nil {
			http.Error(w, "core unavailable", http.StatusServiceUnavailable)
			return
		}
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "core unavailable", http.StatusServiceUnavailable)
			return
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			http.Error(w, "core unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Addr: c.Listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: serverCA}}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 3)
	go func() { done <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	go func() {
		done <- broker.ConsumeExecution(ctx, c.Tenant, c.Connector, func(ctx context.Context, raw []byte) error {
			var command workflow.PreparedCommand
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if len(raw) > 1<<20 || decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
				return eventstore.ErrInvalid
			}
			err := h.Stage(ctx, command)
			if errors.Is(err, kube.ErrInvalid) || errors.Is(err, kube.ErrUnsupported) {
				return eventstore.ErrInvalid
			}
			return err
		}, logger)
	}()
	go func() {
		syncTick := time.NewTicker(15 * time.Second)
		defer syncTick.Stop()
		readTick := time.NewTicker(100 * time.Millisecond)
		defer readTick.Stop()
		// Inventory uses a separate worker: a complete list must not delay the
		// short-lived permit's independent read-back observation.
		syncDone := make(chan error, 1)
		syncBusy := false
		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-syncTick.C:
				if !syncBusy {
					syncBusy = true
					go func() {
						syncCtx, stop := context.WithTimeout(ctx, 30*time.Second)
						defer stop()
						syncDone <- a.PublishSnapshot(syncCtx, private, broker.Publish)
					}()
				}
			case err := <-syncDone:
				syncBusy = false
				if err != nil {
					logger.Warn("native inventory publication pending")
				} else {
					lastSync.Store(time.Now().UnixNano())
				}
			case <-readTick.C:
				if err := h.ReconcileAll(ctx); err != nil {
					logger.Debug("native read-back pending")
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-done:
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	shutdownErr := server.Shutdown(shutdown)
	if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(err, shutdownErr)
}
