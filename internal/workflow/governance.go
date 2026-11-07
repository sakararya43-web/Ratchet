package workflow

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/policy"
)

type PolicyActivation struct {
	Version, Digest, RegistryDigest string
	Epoch, Position                 int64
}

func (s *Service) PolicyHistory(ctx context.Context, actor Actor, after int64, limit int) ([]PolicyActivation, bool, error) {
	if after < 0 || after > 1<<53-1 || limit < 1 || limit > 100 {
		return nil, false, domain.ErrInvalid
	}
	result := []PolicyActivation{}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "policy_history", nil)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT p.version,p.digest,p.registry_epoch,p.event_position,p.raw_bundle,coalesce(p.trust_proof,r.trust_proof,''::bytea) FROM ratchet.policy_artifacts p LEFT JOIN ratchet.registry_artifacts r ON r.tenant_id=p.tenant_id AND r.epoch=p.registry_epoch WHERE p.tenant_id=$1 AND p.event_position>$2 ORDER BY p.event_position LIMIT $3`, actor.TenantID, after, limit+1)
		if err != nil {
			return err
		}
		type record struct {
			version            string
			digest, raw, proof []byte
			epoch, position    int64
		}
		records := []record{}
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.version, &r.digest, &r.epoch, &r.position, &r.raw, &r.proof); err != nil {
				rows.Close()
				return err
			}
			records = append(records, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, r := range records {
			historical, err := policy.PrepareHistorical(ctx, r.proof, active.Root, actor.TenantID, r.raw)
			if err != nil {
				return err
			}
			if historical.Version != r.version || historical.RegistryEpoch != r.epoch || string(historical.Hash[:]) != string(r.digest) {
				return eventstore.ErrIntegrity
			}
			result = append(result, PolicyActivation{r.version, historical.Hash.String(), historical.RegistryDigest.String(), r.epoch, r.position})
		}
		return nil
	})
	more := len(result) > limit
	if more {
		result = result[:limit]
	}
	return result, more, err
}
