package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/telemetry"
)

func (s *Service) decidePolicy(ctx context.Context, tenant, correlation string, a *policy.Active, facts policy.Facts) (decision domain.Decision, err error) {
	ctx, span := s.observer.Start(ctx, "policy_decision", tenant, correlation)
	defer func() { span.End(err) }()
	return a.Decision(ctx, facts)
}

type Diagnostics struct {
	At                           time.Time                  `json:"at"`
	OutboxPending                int64                      `json:"outbox_pending"`
	OutboxOldestSeconds          float64                    `json:"outbox_oldest_seconds"`
	OutboxAttempts               int64                      `json:"outbox_attempts"`
	GraphVersion                 int64                      `json:"durable_graph_version"`
	PublishedGraphVersion        *int64                     `json:"published_graph_version"`
	GraphPublicationLagPositions *int64                     `json:"graph_publication_lag_positions"`
	GraphQuarantined             int64                      `json:"graph_quarantined_sources"`
	GraphObservationAgeSeconds   float64                    `json:"graph_observation_age_seconds"`
	PolicyVersion                string                     `json:"policy_version"`
	RegistryEpoch                int64                      `json:"registry_epoch"`
	JobsDue                      int64                      `json:"jobs_due"`
	JobsFailed                   int64                      `json:"jobs_failed"`
	TemporaryGrantsOverdue       int64                      `json:"temporary_grants_overdue"`
	ExpiryFailures               int64                      `json:"expiry_failures"`
	OpenIncidentOldestSeconds    float64                    `json:"oldest_open_incident_seconds"`
	Spans                        map[string]telemetry.Count `json:"spans"`
}

// Diagnostics contains tenant-local counts/versions only. Observation age is not
// falsely presented as unobserved target lag or verified containment duration.
func (s *Service) Diagnostics(ctx context.Context, tenant string) (Diagnostics, error) {
	return s.diagnostics(ctx, tenant, nil)
}

func (s *Service) InvestigatorDiagnostics(ctx context.Context, actor Actor) (Diagnostics, error) {
	return s.diagnostics(ctx, actor.TenantID, &actor)
}

func (s *Service) diagnostics(ctx context.Context, tenant string, actor *Actor) (Diagnostics, error) {
	d := Diagnostics{}
	if !s.tenants[tenant] {
		return d, ErrPermission
	}
	err := s.Store.WithTenantTx(ctx, tenant, func(tx pgx.Tx, now time.Time) error {
		if actor != nil {
			if _, _, err := s.context(ctx, tx, *actor, "investigate", nil); err != nil {
				return err
			}
		}
		d.At = now
		a, err := s.active(ctx, tx, tenant)
		if err != nil {
			return err
		}
		d.PolicyVersion, d.RegistryEpoch = a.Version, a.RegistryEpoch
		if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(extract(epoch FROM clock_timestamp()-min(created_at)),0)::float8,coalesce(sum(attempts),0)::bigint FROM ratchet.outbox WHERE tenant_id=$1 AND delivered_at IS NULL`, tenant).Scan(&d.OutboxPending, &d.OutboxOldestSeconds, &d.OutboxAttempts); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(s.graph_version),0),count(*) FILTER(WHERE s.needs_resync),coalesce(extract(epoch FROM clock_timestamp()-min(e.recorded_at)),0)::float8 FROM ratchet.graph_sources s LEFT JOIN ratchet.events e ON e.tenant_id=s.tenant_id AND e.sequence=s.graph_version WHERE s.tenant_id=$1`, tenant).Scan(&d.GraphVersion, &d.GraphQuarantined, &d.GraphObservationAgeSeconds); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state IN ('available','retryable','scheduled') AND scheduled_at<=clock_timestamp()),count(*) FILTER(WHERE state IN ('retryable','discarded','cancelled')) FROM ratchet_jobs.river_job WHERE queue=$1 AND args->>'tenant_id'=$2`, tenantQueue(tenant), tenant).Scan(&d.JobsDue, &d.JobsFailed); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='EXECUTED' AND document->>'expiry_status' IN ('SCHEDULED','REVOKING','FAILED') AND (document->>'grant_expires_at')::timestamptz<=clock_timestamp()),count(*) FILTER(WHERE document->>'expiry_status'='FAILED') FROM ratchet.change_projection WHERE tenant_id=$1`, tenant).Scan(&d.TemporaryGrantsOverdue, &d.ExpiryFailures); err != nil {
			return err
		}
		// These are ages of open investigations, not verified containment times.
		rows, err := tx.Query(ctx, `SELECT canonical_content FROM ratchet.events WHERE tenant_id=$1 AND event_type='IncidentOpened'`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var event struct {
				Payload struct {
					Facts struct {
						OpenedAt time.Time `json:"opened_at"`
					} `json:"facts"`
				} `json:"payload"`
			}
			if json.Unmarshal(raw, &event) != nil {
				return domain.ErrInvalid
			}
			if event.Payload.Facts.OpenedAt.IsZero() || event.Payload.Facts.OpenedAt.After(now) {
				return eventstore.ErrIntegrity
			}
			if age := now.Sub(event.Payload.Facts.OpenedAt).Seconds(); age > d.OpenIncidentOldestSeconds {
				d.OpenIncidentOldestSeconds = age
			}
		}
		return rows.Err()
	})
	d.Spans = s.observer.Counts(tenant)
	if err == nil && s.config.PublishedGraphVersion != nil {
		if published, e := s.config.PublishedGraphVersion(ctx, tenant); e == nil {
			lag := max(int64(0), d.GraphVersion-published)
			d.PublishedGraphVersion, d.GraphPublicationLagPositions = &published, &lag
		}
	}
	return d, err
}
