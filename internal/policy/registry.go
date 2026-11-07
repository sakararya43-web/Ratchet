package policy

import (
	"encoding/json"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

// RegistryProof retains the signed transitions needed to verify an epoch from
// the independently pinned original genesis. Claimed history alone is not proof.
type RegistryProof struct {
	Genesis   trust.GenesisState       `json:"genesis"`
	Rotations []trust.RegistryProposal `json:"rotations"`
}
type Registry struct {
	Epoch  int64
	Digest ports.Digest
	Proof  []byte
	Root   ports.Digest
	store  *trust.Store
}

func registryDigest(g *trust.GenesisState) (ports.Digest, error) {
	return canon.New().Digest(struct {
		Domain  string
		Tenant  string
		Root    ports.Digest
		Epoch   int64
		M, N    int
		Members []trust.AuthorityMember
	}{"RATCHET_REGISTRY_CONTEXT_V1", g.TenantID, g.GenesisDigest, g.Epoch, g.ThresholdM, g.TotalN, g.Members})
}

// RegistryFromStore consumes a stable, privately loaded peer store. Runtime
// reloads create a fresh store instead of sharing the peer's mutable pointers.
func RegistryFromStore(source *trust.Store, root ports.Digest, tenant string) (*Registry, error) {
	if source == nil || root.IsZero() || tenant == "" {
		return nil, ErrUnavailable
	}
	current, err := source.GetGenesis()
	if err != nil || current.TenantID != tenant || current.Epoch < 1 || current.Epoch > 256 {
		return nil, ErrInvalid
	}
	proof := RegistryProof{Genesis: *current}
	history := source.GetRegistryHistory()
	if current.Epoch > 1 {
		if len(history) == 0 || history[0].Epoch != 1 {
			return nil, ErrInvalid
		}
		proof.Genesis.Epoch = 1
		proof.Genesis.ThresholdM = history[0].ThresholdM
		proof.Genesis.TotalN = history[0].TotalN
		proof.Genesis.Members = history[0].Members
	}
	proposals := source.ListRegistryProposals()
	for epoch := int64(2); epoch <= current.Epoch; epoch++ {
		var match *trust.RegistryProposal
		for _, p := range proposals {
			if p.Status == "ACTIVATED" && p.TargetEpoch == epoch {
				if match != nil {
					return nil, ErrInvalid
				}
				match = p
			}
		}
		if match == nil {
			return nil, ErrInvalid
		}
		proof.Rotations = append(proof.Rotations, *match)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	r, err := VerifyRegistry(raw, root, tenant)
	if err != nil {
		return nil, err
	}
	expected, err := registryDigest(current)
	if err != nil || expected != r.Digest {
		return nil, ErrInvalid
	}
	return r, nil
}

// VerifyRegistry delegates every rotation signature and quorum verification to
// the actual peer Authority methods. Core verifies framing, continuity and root.
func VerifyRegistry(raw []byte, root ports.Digest, tenant string) (*Registry, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || root.IsZero() {
		return nil, ErrInvalid
	}
	var proof RegistryProof
	if json.Unmarshal(raw, &proof) != nil || proof.Genesis.TenantID != tenant || proof.Genesis.Epoch != 1 || len(proof.Rotations) > 255 {
		return nil, ErrInvalid
	}
	store, err := trust.NewStore("")
	if err != nil {
		return nil, err
	}
	g, err := store.InitGenesis(tenant, proof.Genesis.ThresholdM, proof.Genesis.TotalN, proof.Genesis.Members)
	if err != nil || g.GenesisDigest != root || proof.Genesis.GenesisDigest != root {
		return nil, ErrInvalid
	}
	for _, rotation := range proof.Rotations {
		if rotation.TenantID != tenant || rotation.CurrentEpoch != g.Epoch || rotation.TargetEpoch != g.Epoch+1 {
			return nil, ErrInvalid
		}
		p, err := store.ProposeRegistryChange(tenant, rotation.ProposedM, rotation.ProposedN, rotation.ProposedMembers)
		if err != nil || p.ProposalDigest != rotation.ProposalDigest {
			return nil, ErrInvalid
		}
		for _, sig := range rotation.Signatures {
			if store.SignRegistryProposal(p.ProposalID, sig) != nil {
				return nil, ErrInvalid
			}
		}
		g, err = store.ActivateRegistryProposal(p.ProposalID)
		if err != nil {
			return nil, ErrInvalid
		}
	}
	digest, err := registryDigest(g)
	if err != nil {
		return nil, err
	}
	return &Registry{Epoch: g.Epoch, Digest: digest, Proof: append([]byte(nil), raw...), Root: root, store: store}, nil
}
