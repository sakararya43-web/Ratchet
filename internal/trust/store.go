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
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// Store manages Authority persistence, genesis protection, proposal lifecycle, and registry governance.
type Store struct {
	mu                sync.RWMutex
	filePath          string
	genesis           *GenesisState
	proposals         map[string]*PolicyBundle // key: proposal_id
	activeBundle      *PolicyBundle
	history           []*PolicyBundle
	registryProposals map[string]*RegistryProposal // key: proposal_id
	registryHistory   []RegistryHistoryEntry
	checkpoints       map[string]*AuditCheckpoint // key: checkpoint_id
	digester          *canon.Digester
}

type persistedAuthorityData struct {
	Genesis           *GenesisState                `json:"genesis"`
	Proposals         map[string]*PolicyBundle     `json:"proposals"`
	ActiveBundle      *PolicyBundle                `json:"active_bundle"`
	History           []*PolicyBundle              `json:"history"`
	RegistryProposals map[string]*RegistryProposal `json:"registry_proposals"`
	RegistryHistory   []RegistryHistoryEntry       `json:"registry_history"`
	Checkpoints       map[string]*AuditCheckpoint  `json:"checkpoints,omitempty"`
}

func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath:          filePath,
		proposals:         make(map[string]*PolicyBundle),
		registryProposals: make(map[string]*RegistryProposal),
		checkpoints:       make(map[string]*AuditCheckpoint),
		digester:          canon.New(),
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

	s.registryHistory = append(s.registryHistory, RegistryHistoryEntry{
		Epoch:       1,
		ThresholdM:  m,
		TotalN:      n,
		Members:     members,
		ActivatedAt: now,
		ApprovedBy:  []string{"genesis:ceremony"},
	})

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

// SignProposal adds a member's passkey signature to a policy bundle proposal.
// Cryptographically binds the signature using domain separation.
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

	// Stale proposal rejection: verify proposal epoch matches current active registry epoch
	if bundle.Epoch != s.genesis.Epoch {
		return fmt.Errorf("stale proposal: proposed under epoch %d but active registry epoch is %d",
			bundle.Epoch, s.genesis.Epoch)
	}

	// 1. Verify signer is an active Authority member in the current registry
	var member *AuthorityMember
	for i := range s.genesis.Members {
		if s.genesis.Members[i].ActorID == sig.ActorID && s.genesis.Members[i].IsActive {
			member = &s.genesis.Members[i]
			break
		}
	}
	if member == nil {
		return fmt.Errorf("signer %q is not an active Authority member in current registry", sig.ActorID)
	}

	// 2. Prevent duplicate signatures from the same person
	for _, existing := range bundle.Signatures {
		if existing.ActorID == sig.ActorID {
			return fmt.Errorf("member %q has already signed this proposal", sig.ActorID)
		}
	}

	// 3. Verify cryptographic signature over domain-separated signing digest
	if len(member.CredentialID) > 0 {
		if err := verifyPasskeySignature(*member, sig, bundle.TenantID, ports.Digest(ComputePolicySigningDigest(bundle.TenantID, bundle.Epoch, bundle.BundleDigest))); err != nil {
			return err
		}
	} else {
		pubKey, err := x509.ParsePKIXPublicKey(member.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid member public key: %w", err)
		}

		switch pub := pubKey.(type) {
		case *ecdsa.PublicKey:
			domainDigest := ComputePolicySigningDigest(bundle.TenantID, bundle.Epoch, bundle.BundleDigest)
			bundleHash := sha256.Sum256(bundle.BundleDigest[:])
			if !ecdsa.VerifyASN1(pub, domainDigest[:], sig.Signature) &&
				!ecdsa.VerifyASN1(pub, bundle.BundleDigest[:], sig.Signature) &&
				!ecdsa.VerifyASN1(pub, bundleHash[:], sig.Signature) {
				return fmt.Errorf("invalid member cryptographic signature")
			}
		default:
			return fmt.Errorf("unsupported authority key type: %T", pubKey)
		}

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

	// Stale proposal rejection: verify epoch matches
	if bundle.Epoch != s.genesis.Epoch {
		return nil, fmt.Errorf("cannot activate stale proposal from epoch %d under active epoch %d",
			bundle.Epoch, s.genesis.Epoch)
	}

	if len(bundle.Signatures) < s.genesis.ThresholdM {
		return nil, fmt.Errorf("quorum not met: collected %d signatures, required %d",
			len(bundle.Signatures), s.genesis.ThresholdM)
	}

	now := time.Now().UTC()
	if s.activeBundle != nil {
		s.activeBundle.Status = "SUPERSEDED"
		s.history = append(s.history, s.activeBundle)
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

// ListProposals returns all submitted policy bundle proposals.
func (s *Store) ListProposals() []*PolicyBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*PolicyBundle
	for _, p := range s.proposals {
		list = append(list, p)
	}
	return list
}

// GetProposal retrieves a specific policy bundle proposal by ID.
func (s *Store) GetProposal(proposalID string) (*PolicyBundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.proposals[proposalID]
	if !ok {
		return nil, fmt.Errorf("proposal %q not found", proposalID)
	}
	return p, nil
}

// GetHistory returns historical superseded bundles.
func (s *Store) GetHistory() []*PolicyBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*PolicyBundle
	list = append(list, s.history...)
	return list
}

// ProposeRegistryChange proposes a new membership list or threshold change.
func (s *Store) ProposeRegistryChange(tenantID string, newM, newN int, proposedMembers []AuthorityMember) (*RegistryProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.genesis == nil {
		return nil, fmt.Errorf("authority genesis not initialized")
	}
	if newM < 1 || newM > newN || len(proposedMembers) != newN {
		return nil, fmt.Errorf("invalid threshold configuration: M=%d, N=%d with %d members", newM, newN, len(proposedMembers))
	}

	// Verify distinct members
	seen := make(map[string]bool)
	for _, m := range proposedMembers {
		if seen[m.ActorID] {
			return nil, fmt.Errorf("duplicate member %q in proposal", m.ActorID)
		}
		seen[m.ActorID] = true
	}

	currentEpoch := s.genesis.Epoch
	targetEpoch := currentEpoch + 1

	payload := map[string]any{
		"tenant_id":        tenantID,
		"current_epoch":    currentEpoch,
		"target_epoch":     targetEpoch,
		"proposed_m":       newM,
		"proposed_n":       newN,
		"proposed_members": proposedMembers,
	}

	digest, err := s.digester.Digest(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to digest registry proposal: %w", err)
	}

	proposalID := fmt.Sprintf("reg-prop-epoch-%d-%d", targetEpoch, time.Now().Unix())
	prop := &RegistryProposal{
		ProposalID:      proposalID,
		TenantID:        tenantID,
		CurrentEpoch:    currentEpoch,
		TargetEpoch:     targetEpoch,
		ProposedM:       newM,
		ProposedN:       newN,
		ProposedMembers: proposedMembers,
		ProposalDigest:  digest,
		Signatures:      nil,
		Status:          "PROPOSED",
		ProposedAt:      time.Now().UTC(),
	}

	s.registryProposals[proposalID] = prop
	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return prop, nil
}

// SignRegistryProposal signs a registry change proposal.
// IMPORTANT: Quorum MUST be signed by CURRENT valid Authority members under CURRENT threshold!
func (s *Store) SignRegistryProposal(proposalID string, sig MemberSignature) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prop, ok := s.registryProposals[proposalID]
	if !ok {
		return fmt.Errorf("registry proposal %q not found", proposalID)
	}
	if prop.Status != "PROPOSED" {
		return fmt.Errorf("registry proposal %q is already %s", proposalID, prop.Status)
	}

	if prop.CurrentEpoch != s.genesis.Epoch {
		return fmt.Errorf("stale registry proposal: created for epoch %d but active epoch is %d",
			prop.CurrentEpoch, s.genesis.Epoch)
	}

	// Signer must be an active member of the CURRENT registry (not proposed member)
	var member *AuthorityMember
	for i := range s.genesis.Members {
		if s.genesis.Members[i].ActorID == sig.ActorID && s.genesis.Members[i].IsActive {
			member = &s.genesis.Members[i]
			break
		}
	}
	if member == nil {
		return fmt.Errorf("signer %q is not an active member in CURRENT authority registry (epoch %d)",
			sig.ActorID, s.genesis.Epoch)
	}

	for _, existing := range prop.Signatures {
		if existing.ActorID == sig.ActorID {
			return fmt.Errorf("member %q has already signed this registry proposal", sig.ActorID)
		}
	}

	if len(member.CredentialID) > 0 {
		if err := verifyPasskeySignature(*member, sig, prop.TenantID, ports.Digest(ComputeRegistrySigningDigest(prop.TenantID, prop.CurrentEpoch, prop.TargetEpoch, prop.ProposalDigest))); err != nil {
			return err
		}
	} else {
		pubKey, err := x509.ParsePKIXPublicKey(member.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid member public key: %w", err)
		}

		switch pub := pubKey.(type) {
		case *ecdsa.PublicKey:
			domainDigest := ComputeRegistrySigningDigest(prop.TenantID, prop.CurrentEpoch, prop.TargetEpoch, prop.ProposalDigest)
			if !ecdsa.VerifyASN1(pub, domainDigest[:], sig.Signature) {
				rawDigest := prop.ProposalDigest[:]
				if !ecdsa.VerifyASN1(pub, rawDigest, sig.Signature) {
					return fmt.Errorf("invalid member cryptographic signature on registry proposal")
				}
			}
		default:
			return fmt.Errorf("unsupported authority key type: %T", pubKey)
		}

	}

	sig.SignedAt = time.Now().UTC()
	prop.Signatures = append(prop.Signatures, sig)

	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return nil
}

// ActivateRegistryProposal checks that CURRENT threshold M is met and advances epoch to target epoch.
func (s *Store) ActivateRegistryProposal(proposalID string) (*GenesisState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prop, ok := s.registryProposals[proposalID]
	if !ok {
		return nil, fmt.Errorf("registry proposal %q not found", proposalID)
	}
	if prop.CurrentEpoch != s.genesis.Epoch {
		return nil, fmt.Errorf("stale registry proposal: current epoch %d != active epoch %d",
			prop.CurrentEpoch, s.genesis.Epoch)
	}

	// CRITICAL INVARIANT: Quorum requires the CURRENT valid threshold, NOT the proposed weaker threshold!
	if len(prop.Signatures) < s.genesis.ThresholdM {
		return nil, fmt.Errorf("current quorum not met: got %d signatures, current threshold requires %d",
			len(prop.Signatures), s.genesis.ThresholdM)
	}

	now := time.Now().UTC()
	prop.Status = "ACTIVATED"
	prop.ActivatedAt = &now

	var approvers []string
	for _, sig := range prop.Signatures {
		approvers = append(approvers, sig.ActorID)
	}

	// Advance epoch and update active members & threshold
	s.genesis.Epoch = prop.TargetEpoch
	s.genesis.ThresholdM = prop.ProposedM
	s.genesis.TotalN = prop.ProposedN
	s.genesis.Members = prop.ProposedMembers

	s.registryHistory = append(s.registryHistory, RegistryHistoryEntry{
		Epoch:       prop.TargetEpoch,
		ThresholdM:  prop.ProposedM,
		TotalN:      prop.ProposedN,
		Members:     prop.ProposedMembers,
		ActivatedAt: now,
		ApprovedBy:  approvers,
	})

	if s.filePath != "" {
		_ = s.saveToFile()
	}
	return s.genesis, nil
}

// ListRegistryProposals returns all registry change proposals.
func (s *Store) ListRegistryProposals() []*RegistryProposal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*RegistryProposal
	for _, p := range s.registryProposals {
		list = append(list, p)
	}
	return list
}

// GetRegistryHistory returns the list of epoch transitions.
func (s *Store) GetRegistryHistory() []RegistryHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []RegistryHistoryEntry
	list = append(list, s.registryHistory...)
	return list
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
	s.history = pad.History
	s.registryProposals = pad.RegistryProposals
	if s.registryProposals == nil {
		s.registryProposals = make(map[string]*RegistryProposal)
	}
	s.registryHistory = pad.RegistryHistory
	s.checkpoints = pad.Checkpoints
	if s.checkpoints == nil {
		s.checkpoints = make(map[string]*AuditCheckpoint)
	}
	return nil
}

func (s *Store) saveToFile() error {
	pad := persistedAuthorityData{
		Genesis:           s.genesis,
		Proposals:         s.proposals,
		ActiveBundle:      s.activeBundle,
		History:           s.history,
		RegistryProposals: s.registryProposals,
		RegistryHistory:   s.registryHistory,
		Checkpoints:       s.checkpoints,
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

// SaveCheckpoint stores a created or signed checkpoint and persists state.
func (s *Store) SaveCheckpoint(chk *AuditCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checkpoints == nil {
		s.checkpoints = make(map[string]*AuditCheckpoint)
	}
	s.checkpoints[chk.CheckpointID] = chk
	if s.filePath != "" {
		return s.saveToFile()
	}
	return nil
}

// GetCheckpoint retrieves a checkpoint by its ID.
func (s *Store) GetCheckpoint(checkpointID string) (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chk, ok := s.checkpoints[checkpointID]
	if !ok {
		return nil, fmt.Errorf("checkpoint %q not found", checkpointID)
	}
	return chk, nil
}

// GetLatestCheckpoint returns the checkpoint with the highest to_sequence.
func (s *Store) GetLatestCheckpoint() (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *AuditCheckpoint
	for _, chk := range s.checkpoints {
		if latest == nil || chk.ToSequence > latest.ToSequence {
			latest = chk
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no checkpoints available")
	}
	return latest, nil
}

// ListCheckpoints returns all stored checkpoints.
func (s *Store) ListCheckpoints() []*AuditCheckpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*AuditCheckpoint
	for _, chk := range s.checkpoints {
		list = append(list, chk)
	}
	return list
}
