# Local prototype walkthrough

Start with `python scripts/prototype.py start`. The console is at
`https://localhost:8444`; simulator business endpoints are on
`http://127.0.0.1:58085`. Use the current CA and private account file described in
`prototype-runbook.md`. Keep passwords and enrollment tickets out of Git.

1. Open four isolated browser profiles for `user:rahul-assistant`,
   `user:finance-lead`, `user:sec-lead-1` and `user:sec-lead-2` in
   `tenant-exchange-demo`. Tabs within one profile share a session. Register each
   account's passkey in Passkeys using its operator-issued enrollment ticket.
   If a ticket expired, issue a new one with `scripts/prototype.py invite`.
2. As the intern, request `ROLE_ASSIGN`, identity `user:rahul-assistant`, role
   `role:finance-analyst`, with a business justification. Wait for assessment.
   The finance owner reviews both newly reachable finance resources, the exact
   identity, role, expiry and browser-verified envelope/impact digest, then uses
   their passkey. Wait for `EXECUTED`, which requires signed independent target
   read-back. Wait for Infrastructure to reflect the new assignment before
   submitting a subsequent change.
3. Repeat with `role:wallet-operator`. This tier-0 signing role requires two
   independent security leads. One lead's approval leaves it awaiting approval;
   a second vote from that same actor cannot complete quorum. The other lead
   reviews and approves the exact envelope. Exchange-admin adds IAM control and
   safeguard modification and is subject to stricter rejection/independence rules.
4. Observe real target access with these requests. Before the corresponding grant
   they return 403; after verified execution they return 200. The wallet request
   remains forbidden after only one approval.

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

5. As a security lead, use Audit and the request UUID to inspect submission,
   assessment, independent approval records, execution and verified completion.
   To restore the demonstration's starting access, have the intern submit
   `ROLE_REVOKE` for the wallet and finance roles, one at a time. The wallet's
   security owner and the finance owner independently review and approve the
   corresponding request. Wait for each verified execution and graph
   synchronization. These reductions use actual passkeys, signed commands and
   target receipts; they do not reset target state or erase audit.

`python scripts/prototype-browser.py` repeats the complete journey in one worker
against the actual built console, PostgreSQL, JetStream and simulator. It uses
Chromium virtual CTAP2 authenticators with real native browser WebAuthn and backend
signature verification; this is not a physical-authenticator acceptance claim.
It also checks self-approval, stale context, tampered envelope/challenge, duplicate
quorum, restricted owner graph visibility, ledger hash continuity and authorized
credential revocation. It restores its grants through the real reduction workflow.
Browser evidence and screenshots are private local artifacts under `.local/prototype/`.

Install the pinned test browser once with
`node web/node_modules/playwright/cli.js install chromium`. The test process trusts
the exported CA for HTTP tooling and pins the actual leaf SPKI for its isolated
Chromium instance. It does not modify Windows trust or add any application bypass.
The relevant primary APIs are [Playwright CDP sessions](https://playwright.dev/docs/api/class-cdpsession)
and [Chromium WebAuthn](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/).

Executable containment, full restoration, live Authority administration,
automatic expiry/drift and full offline browser approval proof remain outside
this A/B/C prototype. Their original implementation-plan requirements remain open.
