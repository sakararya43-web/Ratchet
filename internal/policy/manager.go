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
	if err := m.RefreshRegistry(ctx); err != nil {
		return err
	}
	a, err := Prepare(ctx, m.Authority, m.Root, m.Tenant, raw)
	if err != nil {
		return err
	}
	err = m.Store.WithTenantTx(ctx, m.Tenant, func(tx pgx.Tx, _ time.Time) error {
		var prior string
		var digest []byte
		var priorEpoch int64
		err := tx.QueryRow(ctx, `SELECT version,digest,registry_epoch FROM ratchet.policy_artifacts WHERE tenant_id=$1 ORDER BY event_position DESC LIMIT 1`, m.Tenant).Scan(&prior, &digest, &priorEpoch)
		if err == nil {
			if string(digest) == string(a.Hash[:]) {
				return nil
			}
			if !Newer(a.Version, prior) || a.RegistryEpoch < priorEpoch {
				return ErrInvalid
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(stream_version),0) FROM ratchet.events WHERE tenant_id=$1 AND stream_id='policy:bundles'`, m.Tenant).Scan(&revision); err != nil {
			return err
		}
		var currentRegistry []byte
		if err := tx.QueryRow(ctx, `SELECT digest FROM ratchet.registry_artifacts WHERE tenant_id=$1 ORDER BY epoch DESC LIMIT 1`, m.Tenant).Scan(&currentRegistry); err != nil || string(currentRegistry) != string(a.RegistryDigest[:]) {
			return ErrUnavailable
		}
		facts, err := json.Marshal(map[string]any{"bundle_digest": a.Hash.String(), "bundle_version": a.Version, "genesis_digest": m.Root.String(), "registry_epoch": a.RegistryEpoch, "registry_digest": a.RegistryDigest.String()})
		if err != nil {
			return err
		}
		receipt, err := m.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: m.Tenant, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":"+a.Hash.String())), StreamID: "policy:bundles", ExpectedVersion: revision, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":policy-loader")), Events: []eventstore.Event{{Type: "PolicyBundleActivated", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.policy_artifacts(tenant_id,version,digest,raw_bundle,event_position,registry_epoch,trust_proof) VALUES($1,$2,$3,$4,$5,$6,$7)`, m.Tenant, a.Version, a.Hash.Bytes(), raw, receipt.LastSequence, a.RegistryEpoch, a.TrustProof)
		return err
	})
	if err != nil {
		return err
	}
	return m.Engine.Publish(m.Tenant, a)
}
func (m Manager) Restore(ctx context.Context) error {
	if m.Store == nil || m.Engine == nil {
		return ErrUnavailable
	}
	var raw, proof, floor []byte
	err := m.Store.WithTenantTx(ctx, m.Tenant, func(tx pgx.Tx, _ time.Time) error {
		if err := tx.QueryRow(ctx, `SELECT raw_bundle,coalesce(trust_proof,''::bytea) FROM ratchet.policy_artifacts WHERE tenant_id=$1 ORDER BY event_position DESC LIMIT 1`, m.Tenant).Scan(&raw, &proof); err != nil {
			return err
		}
		if len(proof) == 0 {
			return nil
		}
		return tx.QueryRow(ctx, `SELECT trust_proof FROM ratchet.registry_artifacts WHERE tenant_id=$1 ORDER BY epoch DESC LIMIT 1`, m.Tenant).Scan(&floor)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	if len(proof) == 0 {
		return m.Activate(ctx, raw)
	}
	r, err := VerifyRegistry(floor, m.Root, m.Tenant)
	if err != nil {
		return err
	}
	if err := m.Engine.PublishRegistry(m.Tenant, r); err != nil {
		return err
	}
	a, err := PrepareHistorical(ctx, proof, m.Root, m.Tenant, raw)
	if err != nil {
		return err
	}
	return m.Engine.Publish(m.Tenant, a)
}
