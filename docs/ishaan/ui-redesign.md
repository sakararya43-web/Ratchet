# Ratchet UI redesign

The current UI has a seven-section public landing page and a separate authenticated console at `https://localhost:8444/#/console`.

In the local prototype, every landing-page console link opens `/#/console?demo=1` and signs in the requester automatically. Existing signed-in sessions are reused. The console labels this as a demo workspace. To sign in as a reviewer, sign out and use the regular form, or open `/#/console` in a separate browser context. Passkey approvals still require the independent reviewer accounts.

The prototype launcher supplies the provisioned requester password to the core through its private process environment. It is never sent to the browser or embedded in JavaScript. The optional demo endpoint delegates to normal password authentication and is restricted to loopback HTTPS origins. Other deployment profiles do not enable it by default.

## Visual direction

Warm ivory, olive-black, and terracotta; large editorial typography; a custom SVG mechanism and compact technical annotations. The landing sections introduce the product, explain assess/approve/verify, expose the evidence guarantees, and lead into the console. The diagram is explicitly illustrative. Console totals come from authorized backend responses.

The console has a responsive sidebar, an overview with live graph counts, redesigned change and approval surfaces, infrastructure search, impact forms, policy history, incident planning, audit tables, and passkey forms. Existing independent-review, passkey, digest, and target-verification behavior is retained.

## Open and restart

The redesign is running at `https://localhost:8444`. Enter the console from the landing page or use `/#/console` directly.

The local prototype CA is trusted in the current Windows user certificate store. Browser certificate verification is enabled. On a fresh Windows account, or after explicitly renewing local TLS, first run `powershell -File scripts/trust-local-https.ps1`. This verifies the running server against the selected CA before importing its public certificate.

To open a local Chromium window with normal HTTPS verification:

```powershell
node scripts/ui-preview.mjs
```

To restart the saved redesign image without replacing existing data:

```powershell
docker tag ratchet-prototype:ui-redesign ratchet-prototype:local
python scripts/prototype.py start --no-build
```

The earlier `demo-ready` image and recording are retained as the previous milestone. `python scripts/demo.py start` deliberately restores that earlier frozen candidate. For the new UI, use the commands above. The updated presenter launcher enters the console directly and works with either version.

## Performance and accessibility

Native scrolling, native CSS scroll timelines, transform-based artwork, and IntersectionObserver chapter tracking. No per-frame React renders, inherited per-frame CSS updates, scroll interception, external fonts, video downloads, or animation libraries. Reduced-motion preferences disable the motion. Navigation, controls, accordion panels, form labels, focus indicators, and skip links support keyboard use. Older browsers without scroll-timeline support retain the static layout and all controls.

The production JavaScript is 89.30 KB gzipped and CSS is 10.14 KB gzipped. Before the landing expansion, the local HTTPS test measured 332 ms largest-contentful paint, zero cumulative layout shift, and 16.7 ms median / 95th-percentile scroll frames at 4x CPU throttling. One of 178 measured frames exceeded 50 ms. These are local Chromium measurements, not a guarantee for every device or network. Assets are served locally; gzip figures describe build output size, not a claim that the Go server enables compression.

## Verification

- TypeScript and production Vite build; 20 frontend tests; dependency audit with zero reported vulnerabilities.
- Two landing browser tests covering chapter navigation, protocol interaction, evidence accordion, entry/return links, mobile menu, reduced motion, and 360/390/768/1440-pixel widths.
- `node scripts/ui-check.mjs`: all eight authenticated console screens, infrastructure search, session-preserving return from the website, mobile overflow checks, screenshots, keyboard skip link, and local performance sampling. Uses real read-only APIs and an operator-issued local account. No browser runtime errors or external network requests on the landing page.
- Full real-passkey prototype acceptance passed in 48.2 seconds: four independent accounts, verified target execution, rejected self/duplicate/insufficient approvals and tampered context, 270 canonical ledger events, and reviewed revocation cleanup. Evidence is recorded in `.local/ui-redesign/approval-acceptance.log` and `.local/prototype/browser-evidence.json`. These use Chromium virtual CTAP2 authenticators with real backend signature verification, not physical hardware keys.

Evidence and screenshots are under `.local/ui-redesign/`. Keep the entire `.local` directory private; it also contains operator credentials and presenter state elsewhere.

## Expanded landing story

Three additional sections explain transitive access, walk through a clearly labelled Binance incident case study, and connect the graph, control plane, target and audit. A pinned desktop access-path visual rotates with scroll position; narrative beats, access paths and architecture panels reveal as the viewport moves. Mobile layouts reflow into a readable vertical story. All scroll effects use native CSS view timelines and respect reduced-motion settings.
