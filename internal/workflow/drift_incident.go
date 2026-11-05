package workflow

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
)

func (s *Service) appendDriftIncident(ctx context.Context, tx pgx.Tx, incident Incident, kind string) error {
	prior := incident.Revision
	incident.Revision++
	raw, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: incident.Tenant, ID: uuid.NewSHA1(uuid.MustParse(incident.ID), []byte(kind+":"+incident.CorrectiveRequest)), StreamID: "incident:" + incident.ID, ExpectedVersion: prior, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(incident.Tenant+":core-drift-verifier")), Events: []eventstore.Event{{Type: kind, Facts: raw}}})
	return err
}

func (s *Service) recordDriftResultWithin(ctx context.Context, tx pgx.Tx, tenant, request string) error {
	c, err := s.Store.ChangeWithin(ctx, tx, tenant, request)
	if err != nil {
		return err
	}
	if c.State != domain.Executed && c.State != domain.Failed {
		return nil
	}
	incident, err := s.incidentWithin(ctx, tx, tenant, c.IncidentReference, 0)
	if err != nil {
		return err
	}
	if incident.Origin != "DRIFT" || incident.CorrectiveRequest != c.ID || incident.SourceDrift != c.SourceDrift {
		return eventstore.ErrIntegrity
	}
	if c.State == domain.Failed {
		incident.Status = "OPEN"
		return s.appendDriftIncident(ctx, tx, incident, "IncidentCorrectionFailed")
	}
	var result ExecutionResult
	if json.Unmarshal(c.Facts, &result) != nil || !result.Success || !result.ReadBackVerified || result.CommandID != c.ExecutionID {
		return eventstore.ErrIntegrity
	}
	incident.CorrectiveVerifiedAt, incident.ObservedRevision = c.UpdatedAt, result.ObservedRevision
	if err := s.appendDriftIncident(ctx, tx, incident, "IncidentCorrectionVerified"); err != nil {
		return err
	}
	return s.enqueue(ctx, tx, JobArgs{Tenant: tenant, Request: c.ID, Revision: c.Revision, Operation: "incident"})
}

// ReconcileDriftIncident waits for the independently synchronized graph after
// signed target read-back. A verified role removal alone does not prove zero
// residual tier-0 reach. No further corrective write is issued by this worker.
func (s *Service) ReconcileDriftIncident(ctx context.Context, args JobArgs) error {
	if !s.tenants[args.Tenant] {
		return river.JobCancel(ErrPermission)
	}
	return s.Store.WithTenantTx(ctx, args.Tenant, func(tx pgx.Tx, now time.Time) error {
		c, err := s.Store.ChangeWithin(ctx, tx, args.Tenant, args.Request)
		if err != nil {
			return err
		}
		if c.SourceDrift == "" || c.State != domain.Executed {
			return nil
		}
		incident, err := s.incidentWithin(ctx, tx, args.Tenant, c.IncidentReference, 0)
		if err != nil {
			return err
		}
		if incident.Status != "CONTAINING" || incident.CorrectiveVerifiedAt.IsZero() {
			return nil
		}
		var raw []byte
		var command PreparedCommand
		if err := tx.QueryRow(ctx, `SELECT command_payload FROM ratchet.execution_attempts WHERE tenant_id=$1 AND command_id=$2::uuid`, args.Tenant, c.ExecutionID).Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal(raw, &command) != nil {
			return eventstore.ErrIntegrity
		}
		var revision int64
		var sourceRaw []byte
		var quarantined bool
		if err := tx.QueryRow(ctx, `SELECT source_revision,public_graph,needs_resync FROM ratchet.graph_sources WHERE tenant_id=$1 AND connector_id=$2`, args.Tenant, command.Connector).Scan(&revision, &sourceRaw, &quarantined); err != nil {
			return err
		}
		if quarantined || revision < incident.ObservedRevision {
			return river.JobSnooze(time.Second)
		}
		var source struct {
			Edges []struct{ Source, Target, Kind string } `json:"edges"`
		}
		if json.Unmarshal(sourceRaw, &source) != nil {
			return eventstore.ErrIntegrity
		}
		roles := []string{}
		for _, edge := range source.Edges {
			if edge.Source == c.Intent.Target && edge.Kind == "ASSIGNED" {
				roles = append(roles, edge.Target)
			}
		}
		slices.Sort(roles)
		roles = slices.Compact(roles)
		if !slices.Equal(roles, command.ExpectedRoles) {
			incident.Status = "OPEN"
			return s.appendDriftIncident(ctx, tx, incident, "IncidentResidualReviewRequired")
		}
		snapshot, err := s.Store.GraphWithin(ctx, tx, args.Tenant, s.key)
		if err != nil {
			return err
		}
		paths, err := snapshot.PathsTo(incident.Identity, 1000, 1_000_000)
		if err != nil {
			return err
		}
		if paths.Truncated {
			return ErrDependency
		}
		if len(paths.Routes) > 0 {
			incident.Status = "OPEN"
			return s.appendDriftIncident(ctx, tx, incident, "IncidentResidualReviewRequired")
		}
		incident.Status, incident.ContainedAt = "CONTAINED", now
		return s.appendDriftIncident(ctx, tx, incident, "IncidentContained")
	})
}
