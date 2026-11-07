// ratchet-prototype performs local operator setup; it is never a serving API.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/api"
	"github.com/sakararya43-web/Ratchet/internal/connector"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

const tenant = "tenant-exchange-demo"
const connectorID = "connector-sim-01"

type demoUser struct {
	Actor      string `json:"actor_id"`
	Password   string `json:"password"`
	Enrollment string `json:"enrollment_ticket,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: ratchet-prototype init|invite|export|health|renew-tls")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	root := fs.String("root", "/data", "private operator volume root")
	policy := fs.String("policies", "/app/policies", "real Rego directory")
	actor := fs.String("actor", "", "verified recipient actor")
	operation := fs.String("operation", "enroll", "enroll or revoke")
	credential := fs.String("credential", "", "exact credential hex for revocation")
	address := fs.String("url", "https://localhost:8444/readyz", "health URL")
	caFile := fs.String("ca", "/data/core/ca.pem", "trusted local CA")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if os.Args[1] == "health" {
		return health(ctx, *address, *caFile)
	}
	if os.Args[1] == "export" {
		raw, err := os.ReadFile(filepath.Join(*root, "operator", "users.json"))
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(raw)
		return err
	}
	if os.Args[1] == "renew-tls" {
		return certificateFiles(filepath.Join(*root, "core"))
	}
	dsn := os.Getenv("RATCHET_MIGRATION_DSN")
	if dsn == "" {
		return errors.New("local operator migration credentials required")
	}
	if err := eventstore.Migrate(ctx, dsn); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	switch os.Args[1] {
	case "init":
		return initialize(ctx, pool, *root, *policy)
	case "invite":
		ticket, err := api.ProvisionCredentialAuthorization(ctx, pool, api.Principal{TenantID: tenant, ActorID: *actor}, *operation, *credential, time.Hour)
		if err != nil {
			return err
		}
		// Only this explicit operator command exports a one-use secret to its caller.
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"actor_id": *actor, "operation": *operation, "credential_id": *credential, "ticket": ticket})
	default:
		return errors.New("unknown prototype operator operation")
	}
}

func health(ctx context.Context, address, caFile string) error {
	roots := x509.NewCertPool()
	if len(address) > 5 && address[:5] == "https" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(raw) {
			return errors.New("invalid local CA")
		}
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}}
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		return fmt.Errorf("dependency unavailable: HTTP %d", response.StatusCode)
	}
	return nil
}

func writeJSON(path string, value any) error { return connector.WritePrivateJSON(path, value) }
