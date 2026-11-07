// Package bus transports durable core events and authenticated connector input.
package bus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

var tenantToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Broker struct {
	connection *nats.Conn
	js         nats.JetStreamContext
}

func Connect(url string, options ...nats.Option) (*Broker, error) {
	options = append(options, nats.Timeout(3*time.Second), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second), nats.Name("ratchet-core"))
	nc, err := nats.Connect(url, options...)
	if err != nil {
		return nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &Broker{connection: nc, js: js}, nil
}
func (b *Broker) Close() { b.connection.Close() }
func StreamName(tenant, kind string) string {
	h := sha256.Sum256([]byte(tenant))
	return "RATCHET_" + hex.EncodeToString(h[:8]) + "_" + kind
}
func (b *Broker) EnsureTenant(ctx context.Context, tenant string) error {
	if !tenantToken.MatchString(tenant) {
		return eventstore.ErrInvalid
	}
	for _, kind := range []string{"EVENTS", "INGEST", "RESULTS", "DRIFT"} {
		subject := "ratchet." + tenant + ".changes.>"
		if kind == "INGEST" {
			subject = "ratchet." + tenant + ".ingest.sync"
		}
		if kind == "RESULTS" {
			subject = "ratchet." + tenant + ".exec.results"
		}
		if kind == "DRIFT" {
			subject = "ratchet." + tenant + ".drift.reports"
		}
		config := &nats.StreamConfig{Name: StreamName(tenant, kind), Subjects: []string{subject}, Storage: nats.FileStorage, Retention: nats.LimitsPolicy, MaxMsgSize: 1 << 20, MaxAge: 24 * time.Hour, Duplicates: 2 * time.Minute}
		old, err := b.js.StreamInfo(config.Name, nats.Context(ctx))
		if err == nil {
			if len(old.Config.Subjects) != 1 || old.Config.Subjects[0] != subject || old.Config.Storage != nats.FileStorage {
				return errors.New("incompatible existing JetStream configuration")
			}
			continue
		}
		if !errors.Is(err, nats.ErrStreamNotFound) {
			return err
		}
		if _, err := b.js.AddStream(config, nats.Context(ctx)); err != nil {
			return err
		}
	}
	return nil
}
func (b *Broker) Publish(ctx context.Context, subject, id string, payload []byte) error {
	if id == "" || len(payload) == 0 || len(payload) > 1<<20 {
		return eventstore.ErrInvalid
	}
	_, err := b.js.Publish(subject, payload, nats.MsgId(id), nats.Context(ctx))
	return err
}

func (b *Broker) Relay(ctx context.Context, store *eventstore.Store, tenant string, logger *slog.Logger, observers ...*telemetry.Recorder) error {
	if store == nil || logger == nil {
		return eventstore.ErrInvalid
	}
	var observer *telemetry.Recorder
	if len(observers) > 0 {
		observer = observers[0]
	}
	publish := func(ctx context.Context, subject, id string, raw []byte) (err error) {
		correlation, parent := telemetry.TransportContext(raw, id)
		ctx = telemetry.Resume(ctx, parent, tenant, correlation)
		ctx, span := observer.Start(ctx, "outbox", tenant, correlation)
		defer func() { span.End(err) }()
		return b.Publish(ctx, subject, id, raw)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		publication, cancel := context.WithTimeout(ctx, 3*time.Second)
		worked, err := store.DeliverOne(publication, tenant, publish)
		cancel()
		if err != nil {
			backlog, _ := store.OutboxBacklog(ctx, tenant)
			logger.Warn("outbox delivery pending", "tenant", tenant, "pending", backlog.Pending, "attempts", backlog.Attempts)
		}
		if worked && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Consume uses an explicit-ack durable consumer. The handler commits its durable
// business effect before AckSync; a lost ACK can only repeat an idempotent input.
func (b *Broker) Consume(ctx context.Context, tenant string, handler func(context.Context, []byte) error, logger *slog.Logger) error {
	return b.consume(ctx, tenant, "INGEST", "ingest.sync", "core-ingest-v1", handler, logger)
}
func (b *Broker) ConsumeResults(ctx context.Context, tenant string, handler func(context.Context, []byte) error, logger *slog.Logger) error {
	return b.consume(ctx, tenant, "RESULTS", "exec.results", "core-results-v1", handler, logger)
}

func (b *Broker) ConsumeDrift(ctx context.Context, tenant string, handler func(context.Context, []byte) error, logger *slog.Logger) error {
	return b.consume(ctx, tenant, "DRIFT", "drift.reports", "core-drift-v1", handler, logger)
}

// ConsumeExecution binds the connector's own durable command stream. Stage must
// persist authenticated commands before this consumer acknowledges delivery.
func (b *Broker) ConsumeExecution(ctx context.Context, tenant, connector string, handler func(context.Context, []byte) error, logger *slog.Logger) error {
	if !tenantToken.MatchString(connector) || connector == "results" {
		return eventstore.ErrInvalid
	}
	return b.consume(ctx, tenant, "EXEC_"+StreamName(connector, "KEY"), "exec."+connector, "native-commands-v1", handler, logger)
}

func (b *Broker) Ready(ctx context.Context) error {
	if b == nil || !b.connection.IsConnected() {
		return errors.New("broker disconnected")
	}
	return b.connection.FlushWithContext(ctx)
}
func (b *Broker) consume(ctx context.Context, tenant, kind, suffix, durable string, handler func(context.Context, []byte) error, logger *slog.Logger) error {
	if handler == nil || logger == nil || !tenantToken.MatchString(tenant) {
		return eventstore.ErrInvalid
	}
	stream := StreamName(tenant, kind)
	if _, err := b.js.AddConsumer(stream, &nats.ConsumerConfig{Durable: durable, FilterSubject: "ratchet." + tenant + "." + suffix, AckPolicy: nats.AckExplicitPolicy, MaxAckPending: 1, AckWait: 30 * time.Second}, nats.Context(ctx)); err != nil {
		return err
	}
	sub, err := b.js.PullSubscribe("ratchet."+tenant+"."+suffix, durable, nats.Bind(stream, durable))
	if err != nil {
		return err
	}
	defer func() { _ = sub.Unsubscribe() }()
	for {
		wait, cancel := context.WithTimeout(ctx, time.Second)
		messages, err := sub.Fetch(1, nats.Context(wait))
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			return fmt.Errorf("fetch connector input: %w", err)
		}
		for _, msg := range messages {
			err := handler(ctx, msg.Data)
			if err != nil {
				if errors.Is(err, ErrAuthentication) || errors.Is(err, eventstore.ErrInvalid) || errors.Is(err, eventstore.ErrIdempotencyConflict) || errors.Is(err, graph.ErrInvalid) || errors.Is(err, graph.ErrNotFound) {
					if term := msg.Term(); term != nil {
						return term
					}
					logger.Warn("connector message rejected", "tenant", tenant)
					continue
				}
				if nak := msg.NakWithDelay(time.Second); nak != nil {
					return nak
				}
				logger.Warn("connector message retry pending", "tenant", tenant)
				continue
			}
			if err := msg.AckSync(nats.Context(ctx)); err != nil {
				return err
			}
		}
	}
}

func (b *Broker) EnsureExecution(ctx context.Context, tenant, connector string) error {
	if !tenantToken.MatchString(tenant) || !tenantToken.MatchString(connector) || connector == "results" {
		return eventstore.ErrInvalid
	}
	name := StreamName(tenant, "EXEC_"+StreamName(connector, "KEY"))
	subject := "ratchet." + tenant + ".exec." + connector
	old, err := b.js.StreamInfo(name, nats.Context(ctx))
	if err == nil {
		if len(old.Config.Subjects) != 1 || old.Config.Subjects[0] != subject || old.Config.Storage != nats.FileStorage {
			return eventstore.ErrInvalid
		}
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err = b.js.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{subject}, Storage: nats.FileStorage, Retention: nats.LimitsPolicy, MaxMsgSize: 1 << 20, MaxAge: 24 * time.Hour, Duplicates: 2 * time.Minute}, nats.Context(ctx))
	return err
}
