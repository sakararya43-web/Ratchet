package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/sakararya43-web/Ratchet/internal/domain"
	"github.com/sakararya43-web/Ratchet/internal/ledger"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// CheckpointAuthority consumes the actual peer HTTP create/list contract. It
// never signs on behalf of members and never trusts a returned quorum count.
type CheckpointAuthority struct {
	base   string
	client *http.Client
}

func NewCheckpointAuthority(endpoint string, transport http.RoundTripper) (*CheckpointAuthority, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, domain.ErrInvalid
	}
	ip := net.ParseIP(u.Hostname())
	allowed := u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())))
	if !allowed {
		return nil, domain.ErrInvalid
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &CheckpointAuthority{strings.TrimRight(u.String(), "/"), &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func checkpointMatches(candidate ledger.CheckpointCandidate, actual trust.AuditCheckpoint) bool {
	want := candidate.Checkpoint
	digest, err := ledger.CheckpointDigest(actual)
	return err == nil && digest == want.CheckpointDigest && actual.CheckpointDigest == digest && actual.CheckpointID == want.CheckpointID && actual.TenantID == want.TenantID && actual.Epoch == want.Epoch && actual.FromSequence == want.FromSequence && actual.ToSequence == want.ToSequence && actual.MerkleRoot == want.MerkleRoot && actual.PriorCheckpointDigest == want.PriorCheckpointDigest && actual.Algorithm == want.Algorithm
}

func (a *CheckpointAuthority) exchange(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return ErrDependency
	}
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: checkpoint Authority request failed", ErrDependency)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%w: checkpoint Authority HTTP %d", ErrDependency, response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(raw) > 4<<20 || json.Unmarshal(raw, output) != nil {
		return fmt.Errorf("%w: invalid checkpoint Authority response", ErrDependency)
	}
	return nil
}

func (a *CheckpointAuthority) ensure(ctx context.Context, p CheckpointProposal, entries []ledger.Entry) (trust.AuditCheckpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var existing []trust.AuditCheckpoint
	// Peer create overwrites its stored object, including signatures. Always look
	// for the frozen ID first, including after a lost POST acknowledgement.
	if err := a.exchange(ctx, http.MethodGet, "/api/v1/authority/checkpoint/list", nil, &existing); err != nil {
		return trust.AuditCheckpoint{}, err
	}
	var found *trust.AuditCheckpoint
	for i := range existing {
		if existing[i].CheckpointID != p.Candidate.Checkpoint.CheckpointID {
			continue
		}
		if found != nil || !checkpointMatches(p.Candidate, existing[i]) {
			return trust.AuditCheckpoint{}, domain.ErrContextChanged
		}
		found = &existing[i]
	}
	if found != nil {
		return *found, nil
	}
	hashes := make([]string, len(entries))
	for i := range entries {
		hashes[i] = entries[i].Hash.String()
	}
	input := struct {
		Tenant string   `json:"tenant_id"`
		From   int64    `json:"from_sequence"`
		To     int64    `json:"to_sequence"`
		Hashes []string `json:"event_digests"`
		Prior  string   `json:"prior_checkpoint_digest"`
	}{p.Candidate.Checkpoint.TenantID, p.Candidate.Checkpoint.FromSequence, p.Candidate.Checkpoint.ToSequence, hashes, p.Candidate.Checkpoint.PriorCheckpointDigest.String()}
	var returned trust.AuditCheckpoint
	if err := a.exchange(ctx, http.MethodPost, "/api/v1/authority/checkpoint/create", input, &returned); err != nil {
		return returned, err
	}
	if !checkpointMatches(p.Candidate, returned) {
		return returned, domain.ErrContextChanged
	}
	return returned, nil
}

// SubmitCheckpoint serializes this tenant's submissions while making a bounded
// Authority round trip. No approval signature is fabricated or accepted here.
// The durable candidate survives either process losing the HTTP acknowledgement.
func (s *Service) SubmitCheckpoint(ctx context.Context, actor Actor, digest ports.Digest, authority *CheckpointAuthority) (trust.AuditCheckpoint, error) {
	var returned trust.AuditCheckpoint
	if digest.IsZero() {
		return returned, domain.ErrInvalid
	}
	if authority == nil {
		return returned, ErrDependency
	}
	err := s.Store.WithTenantTx(ctx, actor.TenantID, func(tx pgx.Tx, _ time.Time) error {
		_, active, err := s.context(ctx, tx, actor, "checkpoint_manage", nil)
		if err != nil {
			return err
		}
		p, err := s.checkpointProposal(ctx, tx, actor.TenantID, digest, active.Root)
		if err != nil {
			return err
		}
		var old []byte
		var position int64
		err = tx.QueryRow(ctx, `SELECT document,event_position FROM ratchet.accepted_checkpoints WHERE tenant_id=$1 AND digest=$2`, actor.TenantID, digest.Bytes()).Scan(&old, &position)
		if err == nil {
			record, err := s.checkpointRecord(ctx, tx, actor.TenantID, old, position, active.Root)
			returned = record.Evidence.Signed
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if active.RegistryDigest != p.RegistryDigest {
			return domain.ErrContextChanged
		}
		prior, err := s.latestCheckpoint(ctx, tx, actor.TenantID, 0, active.Root)
		if err != nil {
			return err
		}
		var priorDigest ports.Digest
		from := int64(1)
		if prior != nil {
			priorDigest = prior.Evidence.Signed.CheckpointDigest
			from = prior.Evidence.Signed.ToSequence + 1
		}
		if priorDigest != p.Candidate.Checkpoint.PriorCheckpointDigest || from != p.Candidate.Checkpoint.FromSequence {
			return domain.ErrContextChanged
		}
		entries, err := s.checkpointEntries(ctx, tx, actor.TenantID, from, p.Candidate.Checkpoint.ToSequence, p.Candidate.PreviousEventHash)
		if err != nil {
			return err
		}
		// Rebuild before publishing, so a stored candidate is never authority to sign
		// a changed source range even if its immutable artifact remained intact.
		rebuilt, err := ledger.BuildCheckpoint(actor.TenantID, p.Candidate.Checkpoint.Epoch, from, p.Candidate.Checkpoint.ToSequence, p.Candidate.PreviousEventHash, priorDigest, entries)
		if err != nil || rebuilt.Checkpoint.CheckpointDigest != digest {
			return domain.ErrContextChanged
		}
		returned, err = authority.ensure(ctx, p, entries)
		return err
	})
	return returned, err
}
