package workflow

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type Incident struct {
	ID                   string                  `json:"incident_id"`
	Tenant               string                  `json:"tenant_id"`
	CorrelationID        string                  `json:"correlation_id"`
	Identity             string                  `json:"affected_identity"`
	PlanID               string                  `json:"plan_id"`
	PlanDigest           ports.Digest            `json:"plan_digest"`
	Status               string                  `json:"status"`
	OpenedAt             time.Time               `json:"opened_at"`
	Revision             int64                   `json:"revision"`
	OpenFingerprint      ports.Digest            `json:"open_fingerprint"`
	RestorationRequests  []string                `json:"restoration_request_ids"`
	Origin               string                  `json:"origin,omitempty"`
	SourceDrift          string                  `json:"source_drift_id,omitempty"`
	CorrectiveRequest    string                  `json:"corrective_request_id,omitempty"`
	CorrectiveVerifiedAt time.Time               `json:"corrective_verified_at,omitempty"`
	ContainedAt          time.Time               `json:"contained_at,omitempty"`
	ObservedRevision     int64                   `json:"verified_observed_revision,omitempty"`
	Kubernetes           *KubernetesDriftReceipt `json:"kubernetes,omitempty"`
}
type incidentRestoration struct {
	ID            string    `json:"incident_id"`
	Tenant        string    `json:"tenant_id"`
	Request       string    `json:"request_id"`
	CorrelationID string    `json:"correlation_id"`
	At            time.Time `json:"requested_at"`
}
type IncidentView struct {
	Incident           Incident
	Proposal           ContainmentProposal
	Observed           graph.Paths
	ObservedAt         time.Time
	VerifiedCorrection *domain.Change
}
type OpenIncidentInput struct {
	CommandID             uuid.UUID
	CorrelationID, PlanID string
	PlanDigest            ports.Digest
	MinGraphVersion       int64
}
type IncidentPage struct {
	Incidents  []IncidentView
	After, End int64
	More       bool
}

func (s *Service) containmentProposal(ctx context.Context, tx pgx.Tx, tenant, id string) (ContainmentProposal, error) {
	var proposal ContainmentProposal
	var raw, digest []byte
	var position int64
	if err := tx.QueryRow(ctx, `SELECT document,plan_digest,event_position FROM ratchet.containment_plans WHERE tenant_id=$1 AND plan_id=$2`, tenant, id).Scan(&raw, &digest, &position); err != nil {
		return proposal, err
	}
	if json.Unmarshal(raw, &proposal) != nil || proposal.Body.ID != id || proposal.Body.Tenant != tenant || len(proposal.Body.Plan.Origins) != 1 {
		return proposal, eventstore.ErrIntegrity
	}
	expected, err := canon.New().Digest(proposal.Body)
	if err != nil || expected != proposal.Digest || string(expected[:]) != string(digest) {
		return proposal, eventstore.ErrIntegrity
	}
	events, err := s.Store.StreamWithin(ctx, tx, tenant, "containment:"+id)
	if err != nil {
		return proposal, err
	}
	if len(events) < 1 || events[0].Sequence != position || events[0].Type != "ContainmentPlanned" {
		return proposal, eventstore.ErrIntegrity
	}
	var content ledger.Content
	var payload struct {
		Facts json.RawMessage `json:"facts"`
	}
	if json.Unmarshal(events[0].Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil {
		return proposal, eventstore.ErrIntegrity
	}
	actual, err := canon.New().Digest(payload.Facts)
	if err != nil {
		return proposal, err
	}
	want, err := canon.New().Digest(proposal)
	if err != nil || actual != want {
		return proposal, eventstore.ErrIntegrity
	}
	return proposal, nil
}

func (s *Service) incidentWithin(ctx context.Context, tx pgx.Tx, tenant, id string, end int64) (Incident, error) {
	var incident Incident
	events, err := s.Store.StreamWithin(ctx, tx, tenant, "incident:"+id)
	if err != nil {
		return incident, err
	}
	for _, event := range events {
		if end != 0 && event.Sequence > end {
			break
		}
		var content ledger.Content
		var payload struct {
			Facts json.RawMessage `json:"facts"`
		}
		if json.Unmarshal(event.Entry.Canonical, &content) != nil || json.Unmarshal(content.Payload, &payload) != nil {
			return incident, eventstore.ErrIntegrity
		}
		switch event.Type {
		case "IncidentCorrectionVerified", "IncidentCorrectionFailed", "IncidentContained", "IncidentResidualReviewRequired":
			var next Incident
			if json.Unmarshal(payload.Facts, &next) != nil || next.ID != incident.ID || next.Tenant != tenant || next.Revision != incident.Revision+1 || event.StreamVersion != next.Revision || next.Identity != incident.Identity || !next.OpenedAt.Equal(incident.OpenedAt) {
				return incident, eventstore.ErrIntegrity
			}
			if incident.Origin == "DRIFT" {
				if next.CorrectiveRequest != incident.CorrectiveRequest || next.SourceDrift != incident.SourceDrift {
					return incident, eventstore.ErrIntegrity
				}
				c, err := s.Store.ChangeAtWithin(ctx, tx, tenant, next.CorrectiveRequest, event.Sequence)
				if err != nil {
					return incident, err
				}
				if c.IncidentReference != id || c.SourceDrift != incident.SourceDrift {
					return incident, eventstore.ErrIntegrity
				}
				if event.Type == "IncidentCorrectionFailed" {
					if c.State != domain.Failed || next.Status != "OPEN" {
						return incident, eventstore.ErrIntegrity
					}
				} else if c.State != domain.Executed || next.CorrectiveVerifiedAt.IsZero() || next.CorrectiveVerifiedAt.After(event.RecordedAt) || next.ObservedRevision < 1 {
					return incident, eventstore.ErrIntegrity
				}
				if event.Type == "IncidentContained" && (next.Status != "CONTAINED" || next.ContainedAt.Before(next.CorrectiveVerifiedAt) || next.ContainedAt.After(event.RecordedAt)) {
					return incident, eventstore.ErrIntegrity
				}
			} else {
				if event.Type == "IncidentContained" {
					if next.Status != "CONTAINED" || next.ContainedAt.IsZero() || next.ContainedAt.After(event.RecordedAt) || next.PlanID != incident.PlanID || next.PlanDigest != incident.PlanDigest {
						return incident, eventstore.ErrIntegrity
					}
				} else if event.Type == "IncidentResidualReviewRequired" {
					if next.Status != "OPEN" && next.Status != "REVIEW" {
						return incident, eventstore.ErrIntegrity
					}
				} else {
					return incident, eventstore.ErrIntegrity
				}
			}
			incident = next
		case "IncidentDriftOpened":
			if incident.Revision != 0 || event.StreamVersion != 1 || json.Unmarshal(payload.Facts, &incident) != nil || incident.ID != id || incident.Tenant != tenant || incident.Origin != "DRIFT" || incident.SourceDrift == "" || incident.Identity == "" || incident.OpenFingerprint.IsZero() || incident.Revision != 1 || incident.OpenedAt.IsZero() || incident.OpenedAt.After(event.RecordedAt) || incident.PlanID != "" || !incident.PlanDigest.IsZero() {
				return incident, eventstore.ErrIntegrity
			}
			if incident.Status != "OPEN" && incident.Status != "CONTAINING" {
				return incident, eventstore.ErrIntegrity
			}
			if incident.CorrectiveRequest != "" {
				c, err := s.Store.ChangeAtWithin(ctx, tx, tenant, incident.CorrectiveRequest, event.Sequence)
				if err != nil {
					return incident, err
				}
				if c.SourceDrift != incident.SourceDrift || c.IncidentReference != id || c.State != domain.Executing {
					return incident, eventstore.ErrIntegrity
				}
			}
		case "IncidentOpened":
			if incident.Revision != 0 || event.StreamVersion != 1 || json.Unmarshal(payload.Facts, &incident) != nil {
				return incident, eventstore.ErrIntegrity
			}
			if incident.ID != id || incident.Tenant != tenant || incident.Status != "OPEN" || incident.Revision != 1 || incident.Identity == "" || incident.OpenFingerprint.IsZero() || incident.PlanDigest.IsZero() || incident.OpenedAt.After(event.RecordedAt) || len(incident.RestorationRequests) != 0 {
				return incident, eventstore.ErrIntegrity
			}
		case "IncidentRestorationRequested":
			var restoration incidentRestoration
			if incident.Revision == 0 || event.StreamVersion != incident.Revision+1 || json.Unmarshal(payload.Facts, &restoration) != nil || restoration.ID != id || restoration.Tenant != tenant || restoration.At.Before(incident.OpenedAt) || restoration.At.After(event.RecordedAt) || slices.Contains(incident.RestorationRequests, restoration.Request) {
				return incident, eventstore.ErrIntegrity
			}
			change, err := s.Store.ChangeWithin(ctx, tx, tenant, restoration.Request)
			if err != nil {
				return incident, err
			}
			validKinds := map[string]bool{
				"ROLE_ASSIGN":                true,
				"ENABLE_ACCOUNT":             true,
				"RESTORE_SERVICE_PERMISSION": true,
				"ISSUE_SESSION":              true,
			}
			if change.ID == "" || change.Intent.IncidentID != id || !validKinds[change.Intent.Kind] || change.CorrelationID != restoration.CorrelationID {
				return incident, eventstore.ErrIntegrity
			}
			incident.RestorationRequests = append(incident.RestorationRequests, restoration.Request)
			incident.Revision++
		default:
			return incident, eventstore.ErrIntegrity
		}
	}
	if incident.ID == "" {
		return incident, pgx.ErrNoRows
	}
	return incident, nil
}

func (s *Service) validateRestoration(ctx context.Context, tx pgx.Tx, actor Actor, intent domain.Intent) error {
	snapshot, _, err := s.context(ctx, tx, actor, "restore", nil)
	if err != nil {
		return err
	}
	incident, err := s.incidentWithin(ctx, tx, actor.TenantID, intent.IncidentID, 0)
	if err != nil {
		return err
	}
	permitted := false
	if incident.Origin == "DRIFT" {
		if incident.CorrectiveVerifiedAt.IsZero() {
			return domain.ErrTransition
		}
		c, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, incident.CorrectiveRequest)
		if err != nil {
			return err
		}
		permitted = c.State == domain.Executed && c.Intent.Kind == "ROLE_REVOKE" && c.Intent.Target == intent.Target && c.Intent.Access == intent.Access && intent.Kind == "ROLE_ASSIGN"
	} else {
		proposal, err := s.containmentProposal(ctx, tx, actor.TenantID, incident.PlanID)
		if err != nil {
			return err
		}
		if proposal.Digest != incident.PlanDigest {
			return domain.ErrInvalid
		}
		for _, action := range proposal.Body.Plan.Actions {
			switch action.Kind {
			case "ROLE_REVOKE":
				if intent.Kind == "ROLE_ASSIGN" && action.Target == intent.Target && action.Access == intent.Access {
					permitted = true
				}
			case "RESTRICT_ACCOUNT":
				if intent.Kind == "ENABLE_ACCOUNT" && action.Target == intent.Target {
					permitted = true
				}
			case "REMOVE_SERVICE_PERMISSION":
				if intent.Kind == "RESTORE_SERVICE_PERMISSION" && action.Target == intent.Target && action.Access == intent.Access {
					permitted = true
				}
			case "TERMINATE_SESSION":
				if intent.Kind == "ISSUE_SESSION" && action.Target == intent.Target {
					permitted = true
				}
			}
		}
	}
	if !permitted {
		return domain.ErrInvalid
	}
	if intent.Kind == "ROLE_ASSIGN" {
		for _, edge := range snapshot.Data().Edges {
			if edge.Kind == "ASSIGNED" && edge.Source == intent.Target && edge.Target == intent.Access {
				return domain.ErrTransition
			}
		}
	}
	return nil
}

func (s *Service) recordRestoration(ctx context.Context, tx pgx.Tx, actor Actor, request string) error {
	change, err := s.Store.ChangeWithin(ctx, tx, actor.TenantID, request)
	if err != nil {
		return err
	}
	incident, err := s.incidentWithin(ctx, tx, actor.TenantID, change.Intent.IncidentID, 0)
	if err != nil {
		return err
	}
	facts, err := json.Marshal(incidentRestoration{ID: incident.ID, Tenant: actor.TenantID, Request: request, CorrelationID: change.CorrelationID, At: change.CreatedAt})
	if err != nil {
		return err
	}
	_, err = s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":restoration:"+request)), StreamID: "incident:" + incident.ID, ExpectedVersion: incident.Revision, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "IncidentRestorationRequested", Facts: facts}}})
	return err
}

func (s *Service) incidentView(ctx context.Context, tx pgx.Tx, incident Incident, snapshot *graph.Snapshot, now time.Time) (IncidentView, error) {
	view := IncidentView{Incident: incident, ObservedAt: now}
	if incident.Origin == "DRIFT" {
		n, err := snapshot.Node(incident.Identity)
		if err != nil {
			if incident.Kubernetes != nil {
				view.Observed = graph.Paths{Version: snapshot.Version(), Routes: []graph.Route{}, Truncated: true}
				return view, nil
			}
			return view, err
		}
		if !graph.Identity(n.Type) {
			view.Observed = graph.Paths{Version: snapshot.Version(), Routes: []graph.Route{}, Truncated: true}
			return view, nil
		}
		observed, err := snapshot.PathsTo(incident.Identity, 1000, 1_000_000)
		view.Observed = observed
		if err == nil && !incident.CorrectiveVerifiedAt.IsZero() {
			c, e := s.Store.ChangeWithin(ctx, tx, incident.Tenant, incident.CorrectiveRequest)
			if e != nil {
				return view, e
			}
			view.VerifiedCorrection = &c
		}
		return view, err
	}
	proposal, err := s.containmentProposal(ctx, tx, incident.Tenant, incident.PlanID)
	if err != nil {
		return view, err
	}
	if proposal.Digest != incident.PlanDigest || proposal.Body.Plan.Origins[0] != incident.Identity {
		return view, eventstore.ErrIntegrity
	}
	view.Proposal = proposal
	view.Observed, err = snapshot.PathsTo(incident.Identity, 1000, 1_000_000)
	return view, err
}

// OpenIncident opens an investigation of an actual stored proposal. It creates
// no target command and grants no authority to execute the proposal.
func (s *Service) OpenIncident(ctx context.Context, actor Actor, input OpenIncidentInput) (IncidentView, error) {
	var view IncidentView
	if input.CommandID == uuid.Nil || input.PlanDigest.IsZero() || input.MinGraphVersion < 0 || input.MinGraphVersion > ledger.MaxSafeInteger {
		return view, domain.ErrInvalid
	}
	for _, raw := range []*string{&input.PlanID, &input.CorrelationID} {
		if id, err := uuid.Parse(*raw); err != nil || id == uuid.Nil {
			return view, domain.ErrInvalid
		} else {
			*raw = id.String()
		}
	}
	fingerprint, err := canon.New().Digest(struct {
		Actor Actor
		Input OpenIncidentInput
	}{actor, input})
	if err != nil {
		return view, err
	}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":incident:"+input.CommandID.String())).String()
	err = s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, _, err := s.context(ctx, tx, actor, "incident_manage", nil)
		if err != nil {
			return err
		}
		if snapshot.Version() < input.MinGraphVersion {
			return graph.ErrUnavailable
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ratchet.events WHERE tenant_id=$1 AND stream_id=$2)`, actor.TenantID, "incident:"+id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			incident, err := s.incidentWithin(ctx, tx, actor.TenantID, id, 0)
			if err != nil {
				return err
			}
			if incident.OpenFingerprint != fingerprint {
				return eventstore.ErrIdempotencyConflict
			}
			view, err = s.incidentView(ctx, tx, incident, snapshot, now)
			return err
		}
		proposal, err := s.containmentProposal(ctx, tx, actor.TenantID, input.PlanID)
		if err != nil {
			return err
		}
		if proposal.Digest != input.PlanDigest {
			return domain.ErrContextChanged
		}
		incident := Incident{ID: id, Tenant: actor.TenantID, CorrelationID: input.CorrelationID, Identity: proposal.Body.Plan.Origins[0], PlanID: input.PlanID, PlanDigest: proposal.Digest, Status: "OPEN", OpenedAt: now, Revision: 1, OpenFingerprint: fingerprint}
		raw, err := json.Marshal(incident)
		if err != nil {
			return err
		}
		if _, err := s.Store.AppendWithin(ctx, tx, eventstore.Command{TenantID: actor.TenantID, ID: input.CommandID, StreamID: "incident:" + id, ActorReference: uuid.NewSHA1(uuid.NameSpaceOID, []byte(actor.TenantID+":"+actor.ID)), Events: []eventstore.Event{{Type: "IncidentOpened", Facts: raw}}}); err != nil {
			return err
		}
		view, err = s.incidentView(ctx, tx, incident, snapshot, now)
		return err
	})
	return view, err
}

func (s *Service) GetIncident(ctx context.Context, actor Actor, id string) (IncidentView, error) {
	var view IncidentView
	if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
		return view, domain.ErrInvalid
	} else {
		id = parsed.String()
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, _, err := s.context(ctx, tx, actor, "incident_view", nil)
		if err != nil {
			return err
		}
		incident, err := s.incidentWithin(ctx, tx, actor.TenantID, id, 0)
		if err != nil {
			return err
		}
		view, err = s.incidentView(ctx, tx, incident, snapshot, now)
		return err
	})
	return view, err
}

func (s *Service) ListIncidents(ctx context.Context, actor Actor, status string, after, end int64, limit int) (IncidentPage, error) {
	page := IncidentPage{Incidents: []IncidentView{}, After: after, End: end}
	if after < 0 || end < 0 || end > ledger.MaxSafeInteger || limit < 1 || limit > 20 {
		return page, domain.ErrInvalid
	}
	if status != "" && status != "OPEN" && status != "CONTAINING" && status != "CONTAINED" && status != "RESOLVED" {
		return page, domain.ErrInvalid
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, now time.Time) error {
		snapshot, _, err := s.context(ctx, tx, actor, "incident_view", nil)
		if err != nil {
			return err
		}
		var head int64
		if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, actor.TenantID).Scan(&head); err != nil {
			return err
		}
		if page.End == 0 {
			page.End = head
		}
		if after > page.End || page.End > head {
			return domain.ErrInvalid
		}
		rows, err := tx.Query(ctx, `SELECT stream_id,min(sequence) FROM ratchet.events WHERE tenant_id=$1 AND stream_id LIKE 'incident:%' AND sequence<=$2 GROUP BY stream_id HAVING min(sequence)>$3 ORDER BY min(sequence) LIMIT 201`, actor.TenantID, page.End, after)
		if err != nil {
			return err
		}
		type ref struct {
			stream   string
			position int64
		}
		refs := []ref{}
		for rows.Next() {
			var r ref
			if err := rows.Scan(&r.stream, &r.position); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i, r := range refs {
			if i == 200 || len(page.Incidents) == limit {
				page.More = true
				break
			}
			incident, err := s.incidentWithin(ctx, tx, actor.TenantID, r.stream[len("incident:"):], page.End)
			if err != nil {
				return err
			}
			page.After = r.position
			if status != "" && incident.Status != status {
				continue
			}
			view, err := s.incidentView(ctx, tx, incident, snapshot, now)
			if err != nil {
				return err
			}
			page.Incidents = append(page.Incidents, view)
		}
		return nil
	})
	return page, err
}
