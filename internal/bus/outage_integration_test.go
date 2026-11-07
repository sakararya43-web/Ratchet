//go:build integration

package bus_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/bus"
	"github.com/sakararya43-web/Ratchet/internal/testutil/faultproxy"
)

func TestActualBrokerNetworkOutageRetainsOutboxAndRecovers(t *testing.T) {
	l := setup(t)
	endpoint := os.Getenv("RATCHET_NATS_URL")
	if endpoint == "" {
		endpoint = "nats://127.0.0.1:54222"
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	proxy := faultproxy.Start(t, u.Host)
	u.Host = proxy.Address()
	b, err := bus.Connect(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.EnsureTenant(l.ctx, l.tenant); err != nil {
		t.Fatal(err)
	}
	if err := l.ingestor.Handle(l.ctx, l.tenant, sign(t, l, snapshot(l))); err != nil {
		t.Fatal(err)
	}
	proxy.Cut()
	failed, cancel := context.WithTimeout(l.ctx, 300*time.Millisecond)
	if err := b.Ready(failed); err == nil {
		t.Fatal("disconnected broker reported ready")
	}
	if _, err := l.store.DeliverOne(failed, l.tenant, b.Publish); err == nil {
		t.Fatal("broker outage acknowledged outbox")
	}
	cancel()
	backlog, err := l.store.OutboxBacklog(l.ctx, l.tenant)
	if err != nil || backlog.Pending != 1 {
		t.Fatal("outage lost durable work", err)
	}
	proxy.Heal()
	deadline := time.Now().Add(8 * time.Second)
	for {
		probe, stop := context.WithTimeout(l.ctx, 200*time.Millisecond)
		err := b.Ready(probe)
		stop()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not reconnect", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if worked, err := l.store.DeliverOne(l.ctx, l.tenant, b.Publish); err != nil || !worked {
		t.Fatal("durable outbox did not recover", worked, err)
	}
	backlog, err = l.store.OutboxBacklog(l.ctx, l.tenant)
	if err != nil || backlog.Pending != 0 {
		t.Fatal("publication did not settle outbox", err)
	}
}
