package eventstore

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/eventstore/storedb"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

type auditDisplay struct {
	EventType string `json:"event_type"`
	Actor     string `json:"actor_reference"`
	Request   string `json:"request_id,omitempty"`
	Incident  string `json:"incident_id,omitempty"`
	Target    string `json:"target,omitempty"`
	Kind      string `json:"kind,omitempty"`
	State     string `json:"state,omitempty"`
	Decision  string `json:"decision,omitempty"`
	Plan      string `json:"plan_id,omitempty"`
}
type auditFacts struct {
	Change domain.Change `json:"change"`
	Graph  graph.Data    `json:"graph"`
	Body   struct {
		ID   string            `json:"plan_id"`
		Plan graph.Containment `json:"plan"`
	} `json:"body"`
}

func auditMetadata(content ledger.Content) (auditFacts, auditDisplay, error) {
	var payload struct {
		Facts json.RawMessage `json:"facts"`
	}
	if json.Unmarshal(content.Payload, &payload) != nil {
		return auditFacts{}, auditDisplay{}, ErrIntegrity
	}
	var facts auditFacts
	if json.Unmarshal(payload.Facts, &facts) != nil {
		facts = auditFacts{}
	}
	c := facts.Change
	return facts, auditDisplay{EventType: content.EventType, Actor: content.ActorID, Request: c.ID, Incident: c.Intent.IncidentID, Target: c.Intent.Target, Kind: c.Intent.Kind, State: string(c.State), Decision: c.Decision.Outcome, Plan: facts.Body.ID}, nil
}

func (s *Store) projectAudit(ctx context.Context, tx pgx.Tx, content ledger.Content) error {
	facts, display, err := auditMetadata(content)
	if err != nil {
		return err
	}
	c := facts.Change
	refs := []string{}
	add := func(id string) {
		if id != "" {
			refs = append(refs, id)
		}
	}
	add(c.Intent.Target)
	add(c.Intent.Access)
	refs = append(refs, c.Intent.Resources...)
	for _, node := range facts.Graph.Nodes {
		if node.Type == "Resource" || node.Type == "Safeguard" {
			add(node.ID)
		}
	}
	var recorded struct {
		Input struct {
			Impact graph.Impact `json:"impact"`
		} `json:"input"`
	}
	if len(c.Facts) > 0 {
		_ = json.Unmarshal(c.Facts, &recorded)
	}
	for _, item := range recorded.Input.Impact.Affected {
		for _, n := range item.NewResources {
			add(n.ID)
		}
		for _, p := range item.NewPowers {
			add(p.NodeID)
		}
		for _, p := range item.RemovedPowers {
			add(p.NodeID)
		}
		for _, n := range item.Weakened {
			add(n.ID)
		}
	}
	for _, activity := range facts.Body.Plan.Preserved {
		add(activity.Resource)
	}
	for _, activity := range facts.Body.Plan.Removed {
		add(activity.Resource)
	}
	if c.ID != "" {
		var prior []string
		err := tx.QueryRow(ctx, `SELECT resource_refs FROM ratchet.audit_projection WHERE tenant_id=$1 AND request_id=$2 AND sequence<$3 ORDER BY sequence DESC LIMIT 1`, content.TenantID, c.ID, content.Sequence).Scan(&prior)
		if err == nil {
			refs = append(refs, prior...)
		} else if err != pgx.ErrNoRows {
			return err
		}
	}
	slices.Sort(refs)
	refs = slices.Compact(refs)
	raw, err := json.Marshal(display)
	if err != nil {
		return err
	}
	stamp, err := time.Parse(time.RFC3339Nano, content.Timestamp)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ratchet.audit_projection(tenant_id,sequence,actor_reference,request_id,incident_id,resource_refs,recorded_at,display) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, content.TenantID, content.Sequence, content.ActorID, c.ID, c.Intent.IncidentID, refs, stamp, raw)
	return err
}
func (s *Store) ensureAudit(ctx context.Context, tx pgx.Tx, tenant string) error {
	var head, count, first, last int64
	var tip []byte
	if err := tx.QueryRow(ctx, `SELECT sequence,hash FROM ratchet.tenant_heads WHERE tenant_id=$1`, tenant).Scan(&head, &tip); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(min(sequence),0),coalesce(max(sequence),0) FROM ratchet.audit_projection WHERE tenant_id=$1`, tenant).Scan(&count, &first, &last); err != nil {
		return err
	}
	if count == head && last == head && (head == 0 || first == 1) {
		return nil
	}
	return s.rebuildAudit(ctx, tx, tenant, head, tip)
}
func (s *Store) rebuildAudit(ctx context.Context, tx pgx.Tx, tenant string, head int64, tip []byte) error {
	if _, err := tx.Exec(ctx, `DELETE FROM ratchet.audit_projection WHERE tenant_id=$1`, tenant); err != nil {
		return err
	}
	var sequence int64
	var previous ports.Digest
	for sequence < head {
		rows, err := storedb.New(tx).LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: sequence, Limit: 200})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrIntegrity
		}
		for _, row := range rows {
			event, err := decodeRow(s.digester, row)
			if err != nil {
				return err
			}
			content, err := ledger.Verify(s.digester, event.Entry, tenant, sequence+1, previous)
			if err != nil {
				return ErrIntegrity
			}
			if err := s.projectAudit(ctx, tx, content); err != nil {
				return err
			}
			sequence = event.Sequence
			previous = event.Entry.Hash
		}
	}
	if sequence != head || string(previous[:]) != string(tip) {
		return ErrIntegrity
	}
	return nil
}

type AuditFilter struct {
	Actor, Resource, Request, Incident string
	Start, End                         *time.Time
}
type AuditView struct {
	Event   StoredEvent
	Display json.RawMessage
}

func (s *Store) AuditWithin(ctx context.Context, tx pgx.Tx, tenant string, f AuditFilter, after, end int64, limit int) ([]AuditView, int64, error) {
	if after < 0 || end < 0 || limit < 1 || limit > 201 {
		return nil, 0, ErrInvalid
	}
	if err := s.ensureAudit(ctx, tx, tenant); err != nil {
		return nil, 0, err
	}
	var head int64
	if err := tx.QueryRow(ctx, `SELECT sequence FROM ratchet.tenant_heads WHERE tenant_id=$1`, tenant).Scan(&head); err != nil {
		return nil, 0, err
	}
	if end == 0 {
		end = head
	}
	if end > head || after > end {
		return nil, 0, ErrInvalid
	}
	rows, err := tx.Query(ctx, `SELECT sequence,display FROM ratchet.audit_projection WHERE tenant_id=$1 AND sequence>$2 AND sequence<=$3 AND ($4='' OR actor_reference=$4) AND ($5='' OR resource_refs @> ARRAY[$5]::text[]) AND ($6='' OR request_id=$6) AND ($7='' OR incident_id=$7) AND ($8::timestamptz IS NULL OR recorded_at>=$8) AND ($9::timestamptz IS NULL OR recorded_at<=$9) ORDER BY sequence LIMIT $10`, tenant, after, end, f.Actor, f.Resource, f.Request, f.Incident, f.Start, f.End, limit)
	if err != nil {
		return nil, 0, err
	}
	type ref struct {
		sequence int64
		display  []byte
	}
	selected := []ref{}
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.sequence, &r.display); err != nil {
			rows.Close()
			return nil, 0, err
		}
		selected = append(selected, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	result := []AuditView{}
	for _, r := range selected {
		events, err := storedb.New(tx).LoadTenantChain(ctx, storedb.LoadTenantChainParams{TenantID: tenant, Sequence: r.sequence - 1, Limit: 1})
		if err != nil {
			return nil, 0, err
		}
		if len(events) != 1 || events[0].Sequence != r.sequence {
			return nil, 0, ErrIntegrity
		}
		event, err := decodeRow(s.digester, events[0])
		if err != nil {
			return nil, 0, err
		}
		var content ledger.Content
		if json.Unmarshal(event.Entry.Canonical, &content) != nil {
			return nil, 0, ErrIntegrity
		}
		_, expected, err := auditMetadata(content)
		if err != nil {
			return nil, 0, err
		}
		var shown auditDisplay
		if json.Unmarshal(r.display, &shown) != nil || shown != expected || (f.Actor != "" && expected.Actor != f.Actor) || (f.Request != "" && expected.Request != f.Request) || (f.Incident != "" && expected.Incident != f.Incident) || (f.Start != nil && event.RecordedAt.Before(*f.Start)) || (f.End != nil && event.RecordedAt.After(*f.End)) {
			return nil, 0, ErrIntegrity
		}
		display, err := json.Marshal(expected)
		if err != nil {
			return nil, 0, err
		}
		event.Entry.Canonical = nil
		result = append(result, AuditView{event, display})
	}
	return result, end, nil
}
