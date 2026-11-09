# RATCHET: focused prototype demonstration

This is the real local access-review prototype. It demonstrates consequence
assessment, independent passkey approval, verified role execution and an audit
trail against a stateful exchange simulator. It is not full product acceptance.

## Open the prepared demonstration

From the repository root:

```powershell
python scripts/demo.py status
powershell -File scripts/trust-local-https.ps1
python scripts/demo.py present
```

The presenter launcher opens four isolated authenticated Chromium windows, named
Requester, Finance owner, Security lead 1 and Security lead 2. Keep the launcher
running while demonstrating. The requester is brought to the front. These
windows use native WebAuthn with explicitly virtual CTAP2 authenticators and real
backend signature checks; do not describe them as physical hardware-key testing.
The browser uses normal certificate verification. The trust helper verifies the
running service against the selected public CA, then installs that CA in the
current Windows user trust store. It is idempotent; repeat after renewing local
TLS. Browser launchers and acceptance tests do not bypass certificate errors.

The runtime is already prepared. If Docker or the services were stopped, run
`python scripts/demo.py start` first. This parks only the alternate completion
profile and preserves all data volumes. It never resets an existing trust root.
Once the candidate is frozen, this command selects the exact saved image IDs,
even if another development build has changed the local image tag. On a fresh
checkout without a saved candidate it builds from source. A missing frozen image
requires rebuilding and revalidating rather than silently substituting a new one.
The console is `https://localhost:8444` and target probes use
`http://127.0.0.1:58085`.

Use `python scripts/demo.py close` to close presenter windows gracefully without
stopping the runtime. Close the presenter before running automated rehearsal or
recording, so two browser processes do not share the same virtual credential.

To return to the preserved completion profile later, close the presenter, run
`python scripts/prototype.py stop`, then
`python scripts/completion-a.py start --no-build`. Do not rerun fresh-genesis
setup against the already accepted Authority state.

## Five-to-seven-minute story

| Window | Action | Explain and verify |
| --- | --- | --- |
| Requester | Start on Overview. | RATCHET checks what an access change makes possible, then requires independent approval and verified execution. |
| Requester | In Changes, submit `ROLE_ASSIGN` for `user:rahul-assistant`, access `role:finance-analyst`, with a justification. | The account initially cannot read finance reports or sign with the wallet. The request reaches `AWAITING_APPROVAL`. |
| Requester | Inspect the submitted request. | The requester cannot approve their own increase. The review button is disabled in the restricted requester view; the backend also refuses self approval. |
| Finance owner | Filter Changes using the request ID. Choose Review exact change. | Review both finance resources, the changed permissions, quorum one and the verified exact-change digest. |
| Finance owner | Approve reviewed change with passkey. | Wait for `EXECUTED`, which requires independently verified target read-back. A finance-report probe now returns 200. |
| Requester | Submit `ROLE_ASSIGN` for the same identity, access `role:wallet-operator`. | This change exposes tier-0 wallet signing and requires two independent security leads. |
| Security lead 1 | Review and approve the exact change. Reopen its review. | The record shows one of two approvals. Wallet signing still returns 403. A duplicate approval by this same lead is refused. |
| Security lead 2 | Review and approve with this account's passkey. | Wait for `EXECUTED`. Wallet signing now returns 200 after verified target execution. |
| Security lead 1 | Open Audit, enter the wallet request ID and choose Find request audit. | Show the two `ChangeApprovalRecorded` events and `ChangeExecuted`, with linked hashes and request ID. |
| Requester and owners | Submit `ROLE_REVOKE` for wallet, then finance, one at a time. Have security lead 1 review the wallet revocation and the finance owner review the finance revocation. | Wait for verified execution and graph synchronization after each operation. Both business probes return 403 again. No ledger or target reset occurs. |

The requester is `user:rahul-assistant`; the finance owner is
`user:finance-lead`; the two security leads are `user:sec-lead-1` and
`user:sec-lead-2`. The tenant is `tenant-exchange-demo`.

Actual target probes (use a REST client, or `python scripts/demo.py probe`):

```http
POST http://127.0.0.1:58085/api/v1/business/finance-report/read
Content-Type: application/json

{"session_id":"session:intern-workstation-1"}
```

```http
POST http://127.0.0.1:58085/api/v1/business/wallet/sign
Content-Type: application/json

{"session_id":"session:intern-workstation-1","amount_usd":100}
```

These are simulator operations. An initially denied probe must return 403; after
the corresponding verified grant it must return 200. In particular, the wallet
must remain denied after only one security approval. Do not call a queued,
approved or merely dispatched request executed.

## Rehearsal and backup recording

```powershell
python scripts/demo.py rehearse
python scripts/demo.py record
```

Rehearsal runs the complete real browser journey quickly and saves its checks.
Recording runs the same journey with readable captions and pauses, producing
`.local/demo-ready/ratchet-demo.webm`, screenshots and
`recording-evidence.json`. The recording is captioned and has no audio; use the
story above for live narration. Open `.local/demo-ready/index.html` for playback.

An interrupted run is recovered by reviewed role revocations on the next run,
never by clearing the target or deleting history. The normal finishing state is
both demonstration roles absent, so the journey can be repeated.

## Scope to state accurately

Supported here: owner and independent two-lead role review, exact envelope/impact
binding, native browser passkeys, target enforcement/read-back, actual simulator
business probes, audit hash continuity and reviewed role revocation.

Not part of this demo: executable four-action containment, full restoration,
automatic expiry/drift correction, complete offline browser-approval proof,
production hosting or broad Kubernetes parity. Hash continuity verification is
not a claim that every offline authorization proof is fully implemented.
The separate live Authority profile is preserved and is not part of this default
demonstration. Its historical acceptance does not validate this demo candidate.

Passwords, enrollment tickets, cookies and private virtual-authenticator keys stay
inside ignored `.local/` files. Never publish the whole directory, raw browser
reports or `presenter-private.json`. Only the curated video, screenshots and
nonsecret outcome evidence belong in a shareable demonstration package.
