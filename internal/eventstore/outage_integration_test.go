//go:build integration

package eventstore_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/testutil/faultproxy"
)

func TestDatabaseNetworkOutagePreservesAtomicRetry(t *testing.T) {
	ctx, _, _, tenant := setup(t)
	config, err := pgxpool.ParseConfig(runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	proxy := faultproxy.Start(t, net.JoinHostPort(config.ConnConfig.Host, strconv.Itoa(int(config.ConnConfig.Port))))
	host, port, err := net.SplitHostPort(proxy.Address())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Host, config.ConnConfig.Port = host, uint16(n)
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckDatabase(ctx); err != nil {
		t.Fatal(err)
	}
	cmd := command(tenant, "outage:atomic")
	proxy.Cut()
	failed, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if _, err := store.Append(failed, cmd); err == nil {
		t.Fatal("database outage acknowledged write")
	}
	cancel()
	proxy.Heal()
	pool.Reset()
	receipt, err := store.Append(ctx, cmd)
	if err != nil || receipt.FirstSequence != 1 {
		t.Fatal("atomic retry after real network recovery", err)
	}
	duplicate, err := store.Append(ctx, cmd)
	if err != nil || !duplicate.Duplicate {
		t.Fatal("recovery duplicated committed write", err)
	}
	if count, _, err := store.VerifyTenant(ctx, tenant); err != nil || count != 1 {
		t.Fatal("outage damaged chain", count, err)
	}
}
