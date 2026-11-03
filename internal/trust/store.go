package trust

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
)

// Store manages Authority persistence, genesis protection, and proposal lifecycle.
type Store struct {
	mu           sync.RWMutex
	filePath     string
	genesis      *GenesisState
	proposals    map[string]*PolicyBundle // key: proposal_id
	activeBundle *PolicyBundle
	digester     *canon.Digester
}

type persistedAuthorityData struct {
	Genesis      *GenesisState            `json:"genesis"`
	Proposals    map[string]*PolicyBundle `json:"proposals"`
	ActiveBundle *PolicyBundle            `json:"active_bundle"`
}

func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath:  filePath,
		proposals: make(map[string]*PolicyBundle),
		digester:  canon.New(),
	}

	if filePath != "" {
		if _, err := os.Stat(filePath); err == nil {
			if err := s.loadFromFile(); err != nil {
				return nil, fmt.Errorf("failed to load authority store: %w", err)
			}
			return s, nil
		}
	}
	return s, nil
}

// InitGenesis performs the one-time genesis ceremony. Fails if genesis has already occurred.
func (s *Store) InitGenesis(tenantID string, m, n int, members []AuthorityMember) (*GenesisState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.genesis != nil {
		return nil, fmt.Errorf("authority genesis has already been established; cannot reset")
	}

	if m < 1 || m > n || len(members) != n {
		return nil, fmt.Errorf("invalid threshold configuration: M=%d, N=%d with %d members", m, n, len(members))
	}

	// Verify distinct members
	seen := make(map[string]bool)
	for _, member := range members {
		if seen[member.ActorID] {
			return nil, fmt.Errorf("duplicate member %q in genesis", member.ActorID)
		}
		seen[member.ActorID] = true
	}

	now := time.Now().UTC()
	genesisPayload := map[string]any{
		"tenant_id":   tenantID,
		"threshold_m": m,
		"total_n":     n,
		"epoch":       1,
		"members":     members,
	}
	digest, err := s.digester.Digest(genesisPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to digest genesis payload: %w", err)
	}

	s.genesis = &GenesisState{
		TenantID:      tenantID,
		ThresholdM:    m,
		TotalN:        n,
		Epoch:         1,
		Members:       members,
		GenesisDigest: digest,
		InitializedAt: now,
	}

	if s.filePath != "" {
		if err := s.saveToFile(); err != nil {
			return nil, err
		}
	}
	return s.genesis, nil
}

// GetGenesis returns the current genesis and approver registry.
func (s *Store) GetGenesis() (*GenesisState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.genesis == nil {
		return nil, fmt.Errorf("authority genesis not yet established")
	}
	return s.genesis, nil
}

// ProposeBundle submits a new policy bundle proposal and computes its canonical digest.
func (s *Store) ProposeBundle(
	tenantID, bundleVersion, description string,
	modules map[string]string,
	data map[string]any,
) (*PolicyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.genesis == nil {
		return nil, fmt.Errorf("authority genesis not initialized")
	}

	payload := map[string]any{
		"bundle_version": bundleVersion,
		"data":           data,
		"description":    description,
		"epoch":          s.genesis.Epoch,
		"modules":        modules,
		"tenant_id":      tenantID,
	}

	digest, err := s.digester.Digest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to digest proposed bundle: %w", err)
	}

	proposalID := fmt.Sprintf("prop-%s-%d", bundleVersion, time.Now().Unix())
	bundle := &PolicyBundle{
		ProposalID:    proposalID,
		TenantID:      tenantID,
		BundleVersion: bundleVersion,
		Description:   description,
		Epoch:         s.genesis.Epoch,
		Modules:       modules,
		Data:          data,
		BundleDigest:  digest,
		Signatures:    nil,
		Status:        "PROPOSED",
		ProposedAt:    time.Now().UTC(),
	}

	s.proposals[proposalID] = bundle
	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return bundle, nil
}

// SignProposal adds a member's passkey signature to a proposal.
func (s *Store) SignProposal(proposalID string, sig MemberSignature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.proposals[proposalID]
	if !ok {
		return fmt.Errorf("proposal %q not found", proposalID)
	}
	if bundle.Status != "PROPOSED" {
		return fmt.Errorf("proposal %q is already %s", proposalID, bundle.Status)
	}

	// 1. Verify signer is an active Authority member
	var member *AuthorityMember
	for i := range s.genesis.Members {
		if s.genesis.Members[i].ActorID == sig.ActorID && s.genesis.Members[i].IsActive {
			member = &s.genesis.Members[i]
			break
		}
	}
	if member == nil {
		return fmt.Errorf("signer %q is not an active Authority member", sig.ActorID)
	}

	// 2. Prevent duplicate signatures from the same person
	for _, existing := range bundle.Signatures {
		if existing.ActorID == sig.ActorID {
			return fmt.Errorf("member %q has already signed this proposal", sig.ActorID)
		}
	}

	// 3. Verify cryptographic signature over bundle digest
	pubKey, err := x509.ParsePKIXPublicKey(member.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid member public key: %w", err)
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		sigHash := sha256.Sum256(bundle.BundleDigest[:])
		if !ecdsa.VerifyASN1(pub, sigHash[:], sig.Signature) {
			return fmt.Errorf("invalid member cryptographic signature")
		}
	default:
		return fmt.Errorf("unsupported authority key type: %T", pubKey)
	}

	sig.SignedAt = time.Now().UTC()
	bundle.Signatures = append(bundle.Signatures, sig)

	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return nil
}

// ActivateBundle checks quorum and activates the policy bundle.
func (s *Store) ActivateBundle(proposalID string) (*PolicyBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundle, ok := s.proposals[proposalID]
	if !ok {
		return nil, fmt.Errorf("proposal %q not found", proposalID)
	}

	if len(bundle.Signatures) < s.genesis.ThresholdM {
		return nil, fmt.Errorf("quorum not met: collected %d signatures, required %d",
			len(bundle.Signatures), s.genesis.ThresholdM)
	}

	now := time.Now().UTC()
	if s.activeBundle != nil {
		s.activeBundle.Status = "SUPERSEDED"
	}

	bundle.Status = "ACTIVE"
	bundle.ActivatedAt = &now
	s.activeBundle = bundle

	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return bundle, nil
}

// GetActiveBundle returns the currently active, verified policy bundle.
func (s *Store) GetActiveBundle() (*PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.activeBundle == nil {
		return nil, fmt.Errorf("no active policy bundle found in authority")
	}
	return s.activeBundle, nil
}

func (s *Store) loadFromFile() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}
	var pad persistedAuthorityData
	if err := json.Unmarshal(data, &pad); err != nil {
		return err
	}
	s.genesis = pad.Genesis
	s.proposals = pad.Proposals
	if s.proposals == nil {
		s.proposals = make(map[string]*PolicyBundle)
	}
	s.activeBundle = pad.ActiveBundle
	return nil
}

func (s *Store) saveToFile() error {
	pad := persistedAuthorityData{
		Genesis:      s.genesis,
		Proposals:    s.proposals,
		ActiveBundle: s.activeBundle,
	}
	data, err := json.MarshalIndent(pad, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}

	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}
