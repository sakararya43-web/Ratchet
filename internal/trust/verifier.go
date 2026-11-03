package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
)

// BundleVerifier implements ports.BundleVerifier.
// Called by Half A (internal/policy) to verify M-of-N signed bundles.
type BundleVerifier struct {
	store    *Store
	digester *canon.Digester
}

// NewBundleVerifier creates a new BundleVerifier instance backed by an Authority store.
func NewBundleVerifier(store *Store) *BundleVerifier {
	return &BundleVerifier{
		store:    store,
		digester: canon.New(),
	}
}

// Verify implements ports.BundleVerifier.
func (bv *BundleVerifier) Verify(ctx context.Context, raw []byte) (ports.VerifiedBundle, error) {
	if len(raw) == 0 {
		return ports.VerifiedBundle{}, fmt.Errorf("empty policy bundle raw bytes")
	}

	var bundle PolicyBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return ports.VerifiedBundle{}, fmt.Errorf("failed to parse policy bundle JSON: %w", err)
	}

	if bundle.BundleVersion == "" {
		return ports.VerifiedBundle{}, fmt.Errorf("policy bundle missing bundle_version")
	}

	genesis, err := bv.store.GetGenesis()
	if err != nil {
		return ports.VerifiedBundle{}, fmt.Errorf("cannot verify bundle: %w", err)
	}

	// 1. Verify bundle digest against canonical JSON
	payload := map[string]any{
		"bundle_version": bundle.BundleVersion,
		"data":           bundle.Data,
		"description":    bundle.Description,
		"epoch":          bundle.Epoch,
		"modules":        bundle.Modules,
		"tenant_id":      bundle.TenantID,
	}

	expectedDigest, err := bv.digester.Digest(payload)
	if err != nil {
		return ports.VerifiedBundle{}, fmt.Errorf("failed to compute canonical digest for bundle: %w", err)
	}

	if expectedDigest != bundle.BundleDigest {
		return ports.VerifiedBundle{}, fmt.Errorf("bundle digest mismatch: tampering detected")
	}

	// 2. Verify M-of-N signatures from distinct Authority members
	if len(bundle.Signatures) < genesis.ThresholdM {
		return ports.VerifiedBundle{}, fmt.Errorf("quorum failure: bundle has %d signatures, threshold requires %d",
			len(bundle.Signatures), genesis.ThresholdM)
	}

	memberMap := make(map[string]AuthorityMember)
	for _, m := range genesis.Members {
		if m.IsActive {
			memberMap[m.ActorID] = m
		}
	}

	seenSigners := make(map[string]bool)
	var validSignerIDs []string

	sigHash := sha256.Sum256(bundle.BundleDigest[:])

	for _, sig := range bundle.Signatures {
		if seenSigners[sig.ActorID] {
			return ports.VerifiedBundle{}, fmt.Errorf("duplicate signature from member %q", sig.ActorID)
		}

		member, ok := memberMap[sig.ActorID]
		if !ok {
			return ports.VerifiedBundle{}, fmt.Errorf("signer %q is not an authorized authority member", sig.ActorID)
		}

		pubKey, err := x509.ParsePKIXPublicKey(member.PublicKey)
		if err != nil {
			return ports.VerifiedBundle{}, fmt.Errorf("invalid public key for member %q: %w", sig.ActorID, err)
		}

		switch pub := pubKey.(type) {
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, sigHash[:], sig.Signature) {
				return ports.VerifiedBundle{}, fmt.Errorf("cryptographic signature failed for member %q", sig.ActorID)
			}
		default:
			return ports.VerifiedBundle{}, fmt.Errorf("unsupported authority key type: %T", pubKey)
		}

		seenSigners[sig.ActorID] = true
		validSignerIDs = append(validSignerIDs, sig.ActorID)
	}

	if len(validSignerIDs) < genesis.ThresholdM {
		return ports.VerifiedBundle{}, fmt.Errorf("insufficient valid signatures: got %d, required %d",
			len(validSignerIDs), genesis.ThresholdM)
	}

	return ports.VerifiedBundle{
		BundleVersion: bundle.BundleVersion,
		BundleDigest:  bundle.BundleDigest,
		Modules:       bundle.Modules,
		Data:          bundle.Data,
		SignerIDs:     validSignerIDs,
		VerifiedAt:    time.Now().UTC(),
	}, nil
}
