package policy

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

// RefreshRegistry durably observes a verified governance change even when no
// replacement bundle is available. Old-epoch approvals cannot remain eligible.
func (m Manager) RefreshRegistry(ctx context.Context) error {
	if m.Store == nil || m.Engine == nil {
		return ErrUnavailable
	}
	r, err := RegistryFromStore(m.Authority, m.Root, m.Tenant)
	if err != nil {
		return err
	}
	err = m.Store.WithTenantTx(ctx, m.Tenant, func(tx pgx.Tx, _ time.Time) error {
		var epoch int64
		var digest []byte
		err := tx.QueryRow(ctx, `SELECT epoch,digest FROM ratchet.registry_artifacts WHERE tenant_id=$1 ORDER BY epoch DESC LIMIT 1`, m.Tenant).Scan(&epoch, &digest)
		if err == nil {
			if r.Epoch < epoch || (r.Epoch == epoch && string(digest) != string(r.Digest[:])) {
				return ErrInvalid
			}
			if r.Epoch == epoch {
				return nil
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(stream_version),0) FROM ratchet.events WHERE tenant_id=$1 AND stream_id='policy:registry'`, m.Tenant).Scan(&revision); err != nil {
			return err
		}
		proofDigest, err := canon.New().Digest(json.RawMessage(r.Proof))
		if err != nil {
			return err
		}
		facts, err := json.Marshal(map[string]any{"registry_epoch": r.Epoch, "registry_digest": r.Digest.String(), "genesis_digest": m.Root.String(), "proof_digest": proofDigest.String()})
		if err != nil {
			return err
		}
		receipt, err := m.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: m.Tenant, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":registry:"+r.Digest.String())), StreamID: "policy:registry", ExpectedVersion: revision, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(m.Tenant+":registry-loader")), Events: []eventstore.Event{{Type: "AuthorityRegistryActivated", Facts: facts}}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ratchet.registry_artifacts(tenant_id,epoch,digest,trust_proof,event_position) VALUES($1,$2,$3,$4,$5)`, m.Tenant, r.Epoch, r.Digest.Bytes(), r.Proof, receipt.LastSequence)
		return err
	})
	if err != nil {
		return err
	}
	return m.Engine.PublishRegistry(m.Tenant, r)
}
