package authority

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/passkeyevidence"
	"github.com/sakararya43-web/Ratchet/internal/policy"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// Initialize is operator-only and targets the Authority's own database. The
// serving role cannot change the bootstrap allowlist or mutate its event log.
func Initialize(ctx context.Context, pool *pgxpool.Pool, bootstrap Bootstrap) error {
	if bootstrap.Validate() != nil {
		return ErrRefused
	}
	var role string
	if err := pool.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil {
		return err
	}
	if role != "ratchet_migrator" {
		return ErrRefused
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, err = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS authority;
CREATE TABLE IF NOT EXISTS authority.settings(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), document jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS authority.state(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), version bigint NOT NULL, document jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS authority.events(sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, command_id uuid NOT NULL UNIQUE, actor text NOT NULL, input_digest bytea NOT NULL, input jsonb NOT NULL, previous_hash bytea NOT NULL, event_hash bytea NOT NULL, result jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE OR REPLACE FUNCTION authority.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Authority events are immutable'; END $$;
DROP TRIGGER IF EXISTS immutable_events ON authority.events;
CREATE TRIGGER immutable_events BEFORE UPDATE OR DELETE OR TRUNCATE ON authority.events FOR EACH STATEMENT EXECUTE FUNCTION authority.reject_mutation();
REVOKE ALL ON SCHEMA authority FROM PUBLIC;
GRANT USAGE ON SCHEMA authority TO ratchet_runtime;
GRANT SELECT ON authority.settings TO ratchet_runtime;
GRANT SELECT,UPDATE ON authority.state TO ratchet_runtime;
GRANT SELECT,INSERT ON authority.events TO ratchet_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA authority TO ratchet_runtime;`)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(bootstrap)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO authority.settings(singleton,document) VALUES(true,$1) ON CONFLICT DO NOTHING", raw)
	if err != nil {
		return err
	}
	var existing []byte
	if err = tx.QueryRow(ctx, "SELECT document FROM authority.settings").Scan(&existing); err != nil {
		return err
	}
	a, _ := canon.New().Digest(json.RawMessage(raw))
	b, _ := canon.New().Digest(json.RawMessage(existing))
	if a != b {
		return ErrRefused
	}
	initial, _ := json.Marshal(State{Candidates: map[string]trust.AuthorityMember{}, Authority: json.RawMessage(`{}`)})
	if _, err = tx.Exec(ctx, "INSERT INTO authority.state(singleton,version,document) VALUES(true,0,$1) ON CONFLICT DO NOTHING", initial); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type State struct {
	Candidates map[string]trust.AuthorityMember `json:"candidates"`
	Authority  json.RawMessage                  `json:"authority"`
}
type Service struct {
	Pool      *pgxpool.Pool
	Bootstrap Bootstrap
}

func Open(ctx context.Context, pool *pgxpool.Pool) (*Service, error) {
	var unsafe bool
	if err := pool.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR pg_has_role(current_user,'ratchet_migrator','MEMBER') OR has_table_privilege(current_user,'authority.events','UPDATE,DELETE,TRUNCATE') OR has_table_privilege(current_user,'authority.settings','UPDATE,INSERT,DELETE') FROM pg_roles r WHERE rolname=current_user`).Scan(&unsafe); err != nil || unsafe {
		return nil, ErrRefused
	}
	var raw []byte
	if err := pool.QueryRow(ctx, "SELECT document FROM authority.settings").Scan(&raw); err != nil {
		return nil, err
	}
	var bootstrap Bootstrap
	if json.Unmarshal(raw, &bootstrap) != nil || bootstrap.Validate() != nil {
		return nil, ErrRefused
	}
	return &Service{Pool: pool, Bootstrap: bootstrap}, nil
}

func (s *Service) read(ctx context.Context, tx pgx.Tx, lock bool) (State, *trust.Store, int64, error) {
	var state State
	var version int64
	var raw []byte
	query := "SELECT version,document FROM authority.state WHERE singleton"
	if lock {
		query += " FOR UPDATE"
	}
	if err := tx.QueryRow(ctx, query).Scan(&version, &raw); err != nil {
		return state, nil, 0, err
	}
	if json.Unmarshal(raw, &state) != nil || state.Candidates == nil {
		return state, nil, 0, ErrRefused
	}
	var retained []byte
	err := tx.QueryRow(ctx, "SELECT result FROM authority.events ORDER BY sequence DESC LIMIT 1").Scan(&retained)
	if version > 0 {
		a, e1 := canon.New().Digest(json.RawMessage(raw))
		b, e2 := canon.New().Digest(json.RawMessage(retained))
		if err != nil || e1 != nil || e2 != nil || a != b {
			return state, nil, 0, ErrRefused
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return state, nil, 0, ErrRefused
	}
	store, err := trust.Import(state.Authority)
	return state, store, version, err
}

func (s *Service) Prepare(ctx context.Context, actor string, input Input) (Preview, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return Preview{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	_, store, _, err := s.read(ctx, tx, false)
	if err != nil {
		return Preview{}, err
	}
	if err = s.eligible(actor, input, store); err != nil {
		return Preview{}, err
	}
	input.Proof = ports.ApprovalSubmission{}
	digest, err := InputDigest(s.Bootstrap.Tenant, actor, input, store)
	if err != nil {
		return Preview{}, err
	}
	raw, err := canon.New().Canonicalize(input)
	return Preview{input, raw, digest}, err
}

func (s *Service) eligible(actor string, input Input, store *trust.Store) error {
	genesis, err := store.GetGenesis()
	if err != nil {
		if input.Operation != "enroll" || input.Epoch != 0 {
			return ErrRefused
		}
		for _, allowed := range s.Bootstrap.Actors {
			if allowed == actor {
				return nil
			}
		}
		return ErrRefused
	}
	if input.Epoch != genesis.Epoch {
		return ErrRefused
	}
	if input.Operation == "enroll" {
		return nil
	} // candidates have no vote until current quorum activates them
	for _, member := range genesis.Members {
		if member.ActorID == actor && member.IsActive {
			return nil
		}
	}
	return ErrRefused
}

func (s *Service) Apply(ctx context.Context, actor string, input Input) (State, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	state, store, version, err := s.read(ctx, tx, true)
	if err != nil {
		return State{}, err
	}
	fingerprint, err := canon.New().Digest(struct {
		Actor string
		Input Input
	}{actor, input})
	if err != nil {
		return State{}, err
	}
	var prior, priorDigest []byte
	var priorActor string
	err = tx.QueryRow(ctx, "SELECT actor,input_digest,result FROM authority.events WHERE command_id=$1", input.ID).Scan(&priorActor, &priorDigest, &prior)
	if err == nil {
		if priorActor != actor || string(priorDigest) != string(fingerprint[:]) || json.Unmarshal(prior, &state) != nil {
			return State{}, ErrRefused
		}
		return state, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return State{}, err
	}
	if err = s.eligible(actor, input, store); err != nil {
		return State{}, err
	}
	digest, err := InputDigest(s.Bootstrap.Tenant, actor, input, store)
	if err != nil {
		return State{}, err
	}
	var member trust.AuthorityMember
	if input.Operation == "enroll" {
		if input.Member == nil {
			return State{}, ErrRefused
		}
		member = *input.Member
		if member.ActorID != actor || member.RPID != s.Bootstrap.RPID || len(member.Origins) != 1 || member.Origins[0] != s.Bootstrap.Origin || !member.IsActive || len(member.CredentialID) == 0 || !member.EnrolledAt.IsZero() {
			return State{}, ErrRefused
		}
	} else {
		genesis, e := store.GetGenesis()
		if e != nil {
			return State{}, e
		}
		for _, m := range genesis.Members {
			if m.ActorID == actor && m.IsActive {
				member = m
			}
		}
	}
	if input.Proof.ActorID != actor || input.Proof.TenantID != s.Bootstrap.Tenant || string(input.Proof.CredentialID) != string(member.CredentialID) {
		return State{}, ErrRefused
	}
	if _, err = passkeyevidence.Verify(ctx, input.Proof, digest, member.PublicKey, member.RPID, member.Origins); err != nil {
		return State{}, ErrRefused
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return State{}, err
	}
	switch input.Operation {
	case "enroll":
		member.EnrolledAt = now
		state.Candidates[actor] = member
		if _, e := store.GetGenesis(); e != nil {
			members := []trust.AuthorityMember{}
			for _, id := range s.Bootstrap.Actors {
				m, ok := state.Candidates[id]
				if !ok {
					break
				}
				members = append(members, m)
			}
			if len(members) == len(s.Bootstrap.Actors) {
				if validMembers(members, s.Bootstrap.Threshold, state.Candidates) != nil {
					return State{}, ErrRefused
				}
				_, err = store.InitGenesis(s.Bootstrap.Tenant, s.Bootstrap.Threshold, len(members), members)
			}
		}
	case "bundle_propose":
		if len(input.Modules) == 0 || len(input.Modules) > 32 || len(input.Description) > 4000 {
			return State{}, ErrRefused
		}
		if !policy.Newer(input.Version, "0.0.0") {
			return State{}, ErrRefused
		}
		if active, e := store.GetActiveBundle(); e == nil && !policy.Newer(input.Version, active.BundleVersion) {
			return State{}, ErrRefused
		}
		_, err = store.ProposeBundle(s.Bootstrap.Tenant, input.Version, input.Description, input.Modules, input.Data)
	case "bundle_sign":
		err = store.SignProposal(input.Proposal, signature(input.Proof))
	case "bundle_activate":
		candidate, e := store.GetProposal(input.Proposal)
		if e != nil || candidate.Status != "PROPOSED" {
			return State{}, ErrRefused
		}
		if active, e := store.GetActiveBundle(); e == nil && !policy.Newer(candidate.BundleVersion, active.BundleVersion) {
			return State{}, ErrRefused
		}
		genesis, e := store.GetGenesis()
		if e != nil {
			return State{}, e
		}
		bundle, e := json.Marshal(candidate)
		if e != nil {
			return State{}, e
		}
		if _, e = policy.Prepare(ctx, store, genesis.GenesisDigest, s.Bootstrap.Tenant, bundle); e != nil {
			return State{}, e
		}
		_, err = store.ActivateBundle(input.Proposal)
	case "registry_propose":
		if validMembers(input.Members, input.Threshold, state.Candidates) != nil {
			return State{}, ErrRefused
		}
		_, err = store.ProposeRegistryChange(s.Bootstrap.Tenant, input.Threshold, len(input.Members), input.Members)
	case "registry_sign":
		err = store.SignRegistryProposal(input.Proposal, signature(input.Proof))
	case "registry_activate":
		_, err = store.ActivateRegistryProposal(input.Proposal)
	default:
		return State{}, ErrRefused
	}
	if err != nil {
		return State{}, err
	}
	state.Authority, err = store.Export()
	if err != nil {
		return State{}, err
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > 16<<20 {
		return State{}, ErrRefused
	}
	previous := make([]byte, 32)
	err = tx.QueryRow(ctx, "SELECT event_hash FROM authority.events ORDER BY sequence DESC LIMIT 1").Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return State{}, err
	}
	hash, err := canon.New().Digest(struct {
		Previous []byte
		Actor    string
		Input    ports.Digest
		State    State
		At       time.Time
	}{previous, actor, fingerprint, state, now})
	if err != nil {
		return State{}, err
	}
	inputRaw, err := json.Marshal(input)
	if err != nil {
		return State{}, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO authority.events(command_id,actor,input_digest,input,previous_hash,event_hash,result,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", input.ID, actor, fingerprint.Bytes(), inputRaw, previous, hash.Bytes(), raw, now)
	if err != nil {
		return State{}, err
	}
	_, err = tx.Exec(ctx, "UPDATE authority.state SET version=$1,document=$2 WHERE singleton AND version=$3", version+1, raw, version)
	if err != nil {
		return State{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *Service) State(ctx context.Context) (State, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return State{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	state, _, _, err := s.read(ctx, tx, false)
	return state, err
}
