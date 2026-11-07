package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
)

// recover verifies retained public evidence and repairs only mutable projections.
// It needs no privacy key and never publishes an execution command.
func runRecovery(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("recover", flag.ContinueOnError)
	flags.SetOutput(out)
	tenant := flags.String("tenant", "", "explicit tenant to verify")
	rebuild := flags.Bool("rebuild", false, "rebuild change and audit display projections")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || flags.NArg() != 0 {
		return errors.New("recover requires an explicit tenant")
	}
	pool, err := pgxpool.New(ctx, os.Getenv("RATCHET_DATABASE_DSN"))
	if err != nil {
		return errors.New("invalid recovery database configuration")
	}
	defer pool.Close()
	store, err := eventstore.New(pool, canon.New())
	if err != nil {
		return err
	}
	if err := store.CheckRuntimeRole(ctx); err != nil {
		return err
	}
	if err := store.CheckMigrations(ctx); err != nil {
		return err
	}
	sequence, tip, err := store.VerifyTenant(ctx, *tenant)
	if err != nil {
		return err
	}
	snapshot, err := store.ReplayGraph(ctx, *tenant)
	if err != nil && !errors.Is(err, graph.ErrUnavailable) {
		return err
	}
	if *rebuild {
		if err := store.RebuildChanges(ctx, *tenant); err != nil {
			return err
		}
	}
	var changes []domain.Change
	var auditCount int
	err = store.WithTenantTx(ctx, *tenant, func(tx pgx.Tx, _ time.Time) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT substring(stream_id from 8) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'change:%' ORDER BY 1`, *tenant)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			c, err := store.ChangeWithin(ctx, tx, *tenant, id)
			if err != nil {
				return err
			}
			changes = append(changes, c)
		}
		if *rebuild {
			if _, err := tx.Exec(ctx, `DELETE FROM ratchet.audit_projection WHERE tenant_id=$1`, *tenant); err != nil {
				return err
			}
		}
		// AuditWithin rebuilds from a verified contiguous prefix before filtering.
		if _, _, err := store.AuditWithin(ctx, tx, *tenant, eventstore.AuditFilter{}, 0, 0, 1); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM ratchet.audit_projection WHERE tenant_id=$1`, *tenant).Scan(&auditCount)
	})
	if err != nil {
		return err
	}
	changeHash, err := canon.New().Digest(changes)
	if err != nil {
		return err
	}
	result := map[string]any{"tenant_id": *tenant, "sequence": sequence, "tip_digest": tip.String(), "change_count": len(changes), "changes_digest": changeHash.String(), "audit_count": auditCount, "schema_version": eventstore.SchemaVersion}
	if snapshot != nil {
		digest, err := canon.New().Digest(snapshot.Data())
		if err != nil {
			return err
		}
		result["graph_version"], result["graph_digest"] = snapshot.Version(), digest.String()
	}
	end, endTip, err := store.VerifyTenant(ctx, *tenant)
	if err != nil {
		return err
	}
	if end != sequence || endTip != tip {
		return errors.New("tenant advanced during recovery verification; retry with writers quiesced")
	}
	return json.NewEncoder(out).Encode(result)
}
