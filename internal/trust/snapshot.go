package trust

import "encoding/json"

// Export retains complete public trust history and assertions. It contains no
// signing keys. SQL-backed Authority transactions use isolated in-memory stores
// and publish this snapshot only after the database commits.
func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(persistedAuthorityData{Genesis: s.genesis, Proposals: s.proposals,
		ActiveBundle: s.activeBundle, History: s.history, RegistryProposals: s.registryProposals,
		RegistryHistory: s.registryHistory, Checkpoints: s.checkpoints})
}

func Import(raw []byte) (*Store, error) {
	var data persistedAuthorityData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	s, err := NewStore("")
	if err != nil {
		return nil, err
	}
	s.genesis = data.Genesis
	s.activeBundle = data.ActiveBundle
	s.history = data.History
	if data.Proposals != nil {
		s.proposals = data.Proposals
	}
	if data.RegistryProposals != nil {
		s.registryProposals = data.RegistryProposals
	}
	s.registryHistory = data.RegistryHistory
	if data.Checkpoints != nil {
		s.checkpoints = data.Checkpoints
	}
	return s, nil
}
