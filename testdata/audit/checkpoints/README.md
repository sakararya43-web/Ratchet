# Checkpoint evidence handoff fixtures

`valid.json` uses `RATCHET_CHECKPOINT_HISTORY_V1`. Seven genuine canonical,
hash-linked events contain two preparation/acceptance pairs. Two distinct
ECDSA P-256 Authority members sign each checkpoint through the real peer trust
implementation. The first range covers events 1–3; the second covers 4–5 and
therefore includes the first acceptance reference. Its own reference is event 7.
No private keys or personal requester context are included.

`pins.json` is the independently supplied test genesis/tip expectation. In a real
investigation those pins must come from trusted configuration and a separately
retained observation, rather than being trusted merely because an export
contains them. Digest values inside JSON objects use the existing Go peer
`ports.Digest` encoding (32 byte integers); API digest string fields use hex.
`canonical_content` is base64 of the exact stored bytes. Decode it without
round-tripping its JSON before verifying the event.

Every other JSON export must fail:

| Fixture | Deliberate corruption |
|---|---|
| changed-canonical | Changed stored bytes without a matching hash |
| missing-event | A gap in the tenant prefix |
| duplicate-event | A repeated sequence |
| reordered-events | Swapped event positions |
| truncated-tail | Missing acceptance reference at the pinned tip |
| forged-signature | Altered actual Authority signature bytes |
| wrong-prior-checkpoint | Broken checkpoint continuity |
| missing-checkpoint | An acceptance event without its evidence artifact |
| rehashed-fork | Rewritten source facts and a fully recomputed chain, retaining the original signed roots |

`workflow.VerifyCheckpointHistory` consumes the complete prefix, caller-supplied
root/tip pins and all accepted artifacts. It checks canonical bytes and sequence,
root-verified historical registries, every signature, Merkle coverage, contiguous
checkpoint ranges, preparation/acceptance artifact digests and reference positions.
It also rejects the rehashed fork when given that fork's new tip: the original
quorum commitment still fails. The regression suite additionally checks the same
format against an actual PostgreSQL/API export.

This is a chain/checkpoint handoff, not the complete offline decision/approval
package. It contains no assertion that historical browser credentials were
verified. Decision evidence and the peer's approval-key history are separate
requirements. The final two reference events are honestly uncheckpointed until
a subsequent range covers them; they are still included in the pinned hash chain.
