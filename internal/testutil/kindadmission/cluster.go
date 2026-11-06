//go:build integration && kindintegration

// Package kindadmission creates a real isolated cluster whose API server presents
// a client certificate to the tested native webhook. It contains no API emulator.
package kindadmission

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

type Cluster struct {
	Kubeconfig string
	Directory  string
	Listener   net.Listener
	TLS        *tls.Config
	URL        string
	CA         []byte
	Client     tls.Certificate
}

func Start(t *testing.T) *Cluster {
	t.Helper()
	kind := os.Getenv("RATCHET_KIND_BINARY")
	if !filepath.IsAbs(kind) {
		t.Fatal("absolute RATCHET_KIND_BINARY is required for actual admission acceptance")
	}
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ratchet isolated kind admission CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leaf := func(serial int64, client bool) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Ratchet actual kind webhook"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"host.docker.internal", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if client {
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			cert.DNSNames = nil
			cert.IPAddresses = nil
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, caTemplate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}
	server, _, _ := leaf(2, false)
	client, clientPEM, clientKey := leaf(3, true)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA parse")
	}
	c := &Cluster{Kubeconfig: filepath.Join(dir, "kubeconfig"), Directory: dir, Listener: listener, TLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, URL: fmt.Sprintf("https://host.docker.internal:%d/validate", port), CA: caPEM, Client: client}
	write := func(name string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("webhook-credentials.json", map[string]any{"apiVersion": "v1", "kind": "Config", "users": []any{map[string]any{"name": fmt.Sprintf("host.docker.internal:%d", port), "user": map[string]string{"client-certificate-data": base64.StdEncoding.EncodeToString(clientPEM), "client-key-data": base64.StdEncoding.EncodeToString(clientKey)}}}})
	write("admission.json", map[string]any{"apiVersion": "apiserver.config.k8s.io/v1", "kind": "AdmissionConfiguration", "plugins": []any{map[string]any{"name": "ValidatingAdmissionWebhook", "configuration": map[string]string{"apiVersion": "apiserver.config.k8s.io/v1", "kind": "WebhookAdmissionConfiguration", "kubeConfigFile": "/ratchet-admission/webhook-credentials.json"}}}})
	patch := "kind: ClusterConfiguration\napiServer:\n  extraArgs:\n  - name: admission-control-config-file\n    value: /ratchet-admission/admission.json\n  extraVolumes:\n  - name: ratchet-admission\n    hostPath: /ratchet-admission\n    mountPath: /ratchet-admission\n    readOnly: true\n    pathType: Directory\n"
	write("kind.json", map[string]any{"apiVersion": "kind.x-k8s.io/v1alpha4", "kind": "Cluster", "nodes": []any{map[string]any{"role": "control-plane", "image": "kindest/node:v1.37.0", "extraMounts": []any{map[string]any{"hostPath": dir, "containerPath": "/ratchet-admission", "readOnly": true}}, "kubeadmConfigPatches": []string{patch}}}})
	name := "ratchet-p6-admission-" + uuid.NewString()[:8]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, kind, "delete", "cluster", "--name", name).CombinedOutput(); err != nil {
			t.Errorf("delete owned cluster %s: %v %s", name, err, output)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if output, err := exec.CommandContext(ctx, kind, "create", "cluster", "--name", name, "--config", filepath.Join(dir, "kind.json"), "--kubeconfig", c.Kubeconfig, "--wait", "120s").CombinedOutput(); err != nil {
		t.Fatalf("create actual admission cluster: %v %s", err, output)
	}
	t.Logf("created isolated actual admission cluster %s", name)
	return c
}

func (c *Cluster) Command(ctx context.Context, input any, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "kubectl", append([]string{"--kubeconfig", c.Kubeconfig, "--request-timeout=15s"}, args...)...)
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		command.Stdin = bytes.NewReader(raw)
	}
	return command.CombinedOutput()
}

func (c *Cluster) Apply(t *testing.T, ctx context.Context, input any) {
	t.Helper()
	if raw, err := c.Command(ctx, input, "create", "-f", "-"); err != nil {
		t.Fatalf("actual Kubernetes create: %v %s", err, raw)
	}
}

func (c *Cluster) Principals(t *testing.T, ctx context.Context) []kube.Principal {
	t.Helper()
	var out []kube.Principal
	for i, name := range []string{"", "kube-apiserver-kubelet-client", "system:kube-controller-manager", "system:kube-scheduler", "system:kube-proxy"} {
		args := []string{"auth", "whoami", "-o", "json"}
		if name != "" {
			args = append([]string{"--as", name}, args...)
		}
		raw, err := c.Command(ctx, nil, args...)
		if err != nil {
			t.Fatalf("actual native identity: %v %s", err, raw)
		}
		var identity struct {
			Status struct {
				User kube.UserInfo `json:"userInfo"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			t.Fatal(err)
		}
		id := "native:" + name
		if i == 0 {
			id = "requester"
		}
		credential := ""
		if values := identity.Status.User.Extra["authentication.kubernetes.io/credential-id"]; len(values) == 1 {
			credential = values[0]
		}
		out = append(out, kube.Principal{ID: id, Kind: "User", Name: identity.Status.User.Username, UID: identity.Status.User.UID, Groups: identity.Status.User.Groups, CredentialID: credential})
	}
	return append(out, kube.Principal{ID: "anonymous", Kind: "User", Name: "system:anonymous", Groups: []string{"system:unauthenticated"}})
}

func (c *Cluster) WebhookConfiguration(name string) any {
	return map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration", "metadata": map[string]string{"name": name}, "webhooks": []any{map[string]any{"name": "native.ratchet.test", "admissionReviewVersions": []string{"v1"}, "sideEffects": "None", "failurePolicy": "Fail", "matchPolicy": "Exact", "timeoutSeconds": 5, "clientConfig": map[string]string{"url": c.URL, "caBundle": base64.StdEncoding.EncodeToString(c.CA)}, "rules": []any{map[string]any{"apiGroups": []string{kube.RBACGroup}, "apiVersions": []string{"v1"}, "operations": []string{"CREATE", "UPDATE", "DELETE"}, "resources": []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"}, "scope": "*"}}}}}
}
