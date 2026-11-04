package policy

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

type Manager struct {
	Store     *eventstore.Store
	Engine    *Engine
	Authority *trust.Store
	Root      ports.Digest
	Tenant    string
}

func (m Manager) Activate(ctx context.Context, raw []byte) error {
	if m.Store == nil || m.Engine == nil {
		return ErrUnavailable
	}
	a, err := Prepare(ctx, m.Authority, m.Root, m.Tenant, raw)
	if err != nil {
		return err
	}
	err = m.Store.WithTenantTx(ctx, m.Tenant, func(tx pgx.Tx, _ time.Time) error {
		var prior string
		var digest []byte
		err := tx.QueryRow(ctx, `SELECT version,digest FROM ratchet.policy_artifacts WHERE tenant_id=$1 ORDER BY event_position DESC LIMIT 1`, m.Tenant).Scan(&prior, &digest)
		if err == nil {
			if string(digest) == string(a.Hash[:]) {
				return nil
			}
			if !Newer(a.Version, prior) {
				return ErrInvalid
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(stream_version),0) FROM ratchet.events WHERE tenant_id=$1 AND stream_id='policy:bundles'`, m.Tenant).Scan(&revision); err != nil {
			return err
		}
		facts, err := json.Marshal(map[string]any{"bundle_digest": a.Hash.String(), "bundle_version": a.Version, "genesis_digest": m.Root.String(), "registry_epoch": 1})
		if err != nil {
			return err
		}
		receipt, err := m.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: m.Tenant, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":"+a.Hash.String())), StreamID: "policy:bundles", ExpectedVersion: revision, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":policy-loader")), Events: []eventstore.Event{{Type: "PolicyBundleActivated", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.policy_artifacts(tenant_id,version,digest,raw_bundle,event_position) VALUES($1,$2,$3,$4,$5)`, m.Tenant, a.Version, a.Hash.Bytes(), raw, receipt.LastSequence)
		return err
	})
	if err != nil {
		return err
	}
	return m.Engine.Publish(m.Tenant, a)
}
func (m Manager) Restore(ctx context.Context) error {
	var raw []byte
	err := m.Store.WithTenantTx(ctx, m.Tenant, func(tx pgx.Tx, _ time.Time) error {
		return tx.QueryRow(ctx, `SELECT raw_bundle FROM ratchet.policy_artifacts WHERE tenant_id=$1 ORDER BY event_position DESC LIMIT 1`, m.Tenant).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	return m.Activate(ctx, raw)
}
