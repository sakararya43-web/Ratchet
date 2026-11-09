# RATCHET demo video: script and production brief

A 3-minute product demo, filmed from the hosted demo at
**https://sakararya43-web.github.io/Ratchet/** with
[openvidstudio](https://github.com/AnayDhawan/openvidstudio).

| | |
|---|---|
| **Length** | 3:00, in 14 beats |
| **Main role** | Alice Vance, security lead and incident responder |
| **Cameo** | Rahul Sharma, the requester, to show that anyone can switch roles |
| **Audience** | Hackathon judges and security teams seeing RATCHET for the first time |
| **Tone** | Plain, direct and confident. No hype words |
| **Creative level** | mid: strong defaults, with an authored hook and end card |
| **Machine-readable plan** | [`capture-plan.json`](capture-plan.json): every beat's URL, interactions, duration and narration |

---

## 1. The prompt

Paste this into your agent from inside the RATCHET repository. openvidstudio must already be installed.

```text
Make a 3-minute product demo video of RATCHET with openvidstudio.

Film the hosted demo at https://sakararya43-web.github.io/Ratchet/. It is a static
site: a fictional crypto exchange called Northwind, running on mock data in the
browser. There is nothing to start and no login. Do not run the Go backend,
Docker or the local prototype.

Follow docs/demo-video/script.md and docs/demo-video/capture-plan.json exactly.
The capture plan has 14 beats with their url, interactions, durations, captions
and narration. Every interaction was replayed in a fresh Chromium at 1600x900
against the live site and reaches its end state. Use it as the beats file: keep
the beat ids, order, durations and narration as written, viewport 1600x900,
deviceScaleFactor 2. Run validate_beats before the approval gate.

Creative level: mid. Narration tone: default. Audience: hackathon judges and
security teams who have never seen RATCHET.

Brand: run extract_brand on this repo, then make the design system use these
roles. Paper #f4f3eb as the background. Ink #23251f for text. Dark olive #242720
for dark panels. Signal orange #e35b35, used sparingly, only for risk, tier 0
and the one key moment in each chapter. Sage #e5ebd9, #c3cfaf and #545e43 for
verified and safe states. Muted #71736a for secondary text, hairlines #d6d7cd.
Type: Helvetica Neue for UI and titles, Georgia italic for one accent word per
title card, Consolas in uppercase with wide letter spacing for eyebrows and
chapter labels. The look is editorial and calm, like a printed security report:
plenty of paper, thin rules, no neon, no glow, no dark hacker look, no matrix
code, no stock footage.

Each beat is captured in a fresh browser, so its interactions include their own
setup. Trim that setup off the start of each clip so every beat opens on the
moment its narration is about. Push the camera in slowly toward the element the
narration names, and arc the cursor to each click. Show the chapter HUD from the
script. Compose an original, restrained score with no drums that builds a little
into Contain and resolves at Prove. Use soft clicks on interactions and the
success tone on "Chain integrity verified".

Honesty: everything on screen is fictional mock data, and the passkey prompt is
simulated. The narration says so; keep it. Keep the "Demo data · fictional
exchange" badge visible whenever the console is on screen. Do not add claims
the frames do not show, and never say RATCHET would have prevented a real
incident. No em dashes anywhere.

Show me the full beats file and the plan_production estimate before anything is
rendered. Render a draft first, then the final mp4 with finalize_video.
```

---

## 2. Why Alice

Alice Vance is the one persona who touches every workspace in the story:

- reviews the tier-0 request;
- runs the impact simulation and traces the access graph;
- reads the signed policy;
- plans and executes containment;
- verifies the audit chain.

Bob only gives a second approval, and Rahul and Priya are refused the organisation-wide views. Rahul appears once near the end, to show that the viewer can switch roles and see the console narrow to a requester's view.

---

## 3. Look and feel

The video should look like the product: a calm, printed security report, not a cyber thriller.

| Role | Colour | Use |
|---|---|---|
| Paper | `#f4f3eb` | Background of every frame and card |
| Ink | `#23251f` | Titles, narration captions |
| Dark olive | `#242720` | The console sidebar; dark title cards |
| Signal orange | `#e35b35` | Risk, tier 0, the orange route, one emphasis per chapter |
| Sage | `#e5ebd9` · `#c3cfaf` · `#545e43` | Verified, safe, "remains operational" |
| Muted | `#71736a` | Secondary text |
| Hairline | `#d6d7cd` | Rules and frames |
| Demo badge | `#f8e6dc` on `#9a3d1f` | Leave it visible; it tells viewers the data is fictional |

| Type | Font | Use |
|---|---|---|
| UI and titles | Helvetica Neue, Arial | Everything by default |
| Accent | Georgia italic | One word per title card, as on the site: "a *boundary*.", "*Before* it changes." |
| Labels | Consolas, uppercase, wide tracking | Eyebrows and the chapter HUD: `02 / ASSESS` |

- **Motion:** slow push-ins, gentle settles and cursor arcs. Hard cuts only on chapter changes.
- **Sound:** a restrained original score with no drums. Soft clicks on interactions, and one success tone on "Chain integrity verified".
- **Avoid:** neon, glow, glitch effects, hooded hackers, falling code, stock footage, and red alarm flashes.

---

## 4. Story arc

| # | Chapter | Beats | What the viewer learns |
|---|---|---|---|
| 01 | The problem | hook | One valid login can become control of everything |
| 02 | Meet RATCHET | meet-ratchet, pick-a-role | What it is; the demo is fictional and you can be anyone |
| 03 | Assess | overview, rejected, review, impact, trace | Every change is judged by what it would unlock |
| 04 | Govern | policy | The rules are signed by independent people |
| 05 | Contain | plan, contain | Take power away fast, without stopping the business |
| 06 | Prove | audit | Every step is on a tamper-evident record |
| 07 | Your turn | switch-role, close | Switch roles and try it yourself |

---

## 5. Shot list

Times are cumulative. Narration is paced at 2.3 to 2.9 words per second, as openvidstudio requires. Captions are short on-screen labels, separate from the narration.

### 0:00 · hook · 13s

**On screen:** the landing page hero, "Power needs a *boundary*." A slow push-in toward the headline.

**Caption:** One stolen session.

**Narration:**
> One stolen session should not cost a company everything. Yet attackers keep turning a single valid login into control of the systems that matter most, one quiet permission at a time.

### 0:13 · meet-ratchet · 11s

**On screen:** the landing page scrolls to "Good intentions. Hard boundaries." and "A small grant. A much bigger reach."

**Caption:** Built for DataNova 2026

**Narration:**
> This is RATCHET, built for the DataNova 2026 Global Data-Thon. Before any access change happens, it shows what that change would unlock, and who must approve it.

### 0:24 · pick-a-role · 13s

**On screen:** the persona sign-in. The cursor passes over Rahul, Priya and Bob, then picks Alice Vance.

**Caption:** Fictional exchange · mock data

**Narration:**
> The live demo runs Northwind, a fictional crypto exchange with mock data, right in your browser. You can sign in as any of four people. We will be Alice, a security lead.

### 0:37 · overview · 12s

**On screen:** the Overview as Alice, then the attention queue: the CRITICAL incident `inc-2002`, and `req-1007` awaiting approval.

**Caption:** Signed in as Alice · Security lead

**Narration:**
> Alice sees the whole organisation, and the attention queue already shows trouble: a critical incident on Rahul's laptop session, and a risky access request waiting for review right now.

### 0:49 · rejected · 13s

**On screen:** Changes. `req-1006` opens as REJECTED, with "Rule 2 of change.rego: tier-0 safeguard weakening is prohibited".

**Caption:** Rejected by signed policy

**Narration:**
> Earlier tonight, someone using Rahul's session tried to cut the withdrawal rule down to a single approval. The signed policy rejected it outright, because nobody may weaken a tier zero safeguard.

### 1:02 · review · 15s

**On screen:** "Review exact change" on `req-1007`:

- 0 of 2 approvals, from two security leads;
- the newly reachable tier-0 resources;
- then "Canonical envelope digest verified in this browser".

**Caption:** Two independent leads · no self-approval

**Narration:**
> Next, the same session asked to become Exchange Administrator. RATCHET sends that request to two independent security leads and refuses self approval. Before any passkey prompt, the browser rechecks the exact change it would sign.

### 1:17 · impact · 14s

**On screen:** the Impact simulation for Rahul and Exchange Administrator:

- "Escalation detected";
- access before and after;
- tier-0 blast radius from 1 to 3;
- the new critical paths.

**Caption:** Simulation only · nothing is changed

**Narration:**
> So what would approval actually unlock? The impact simulation answers before anyone even decides: admin rights over the hot wallet signer and the customer database, plus the power to change the withdrawal rule.

### 1:31 · trace · 13s

**On screen:** Infrastructure, traced to tier 0. The route runs Rahul's laptop session → Rahul → Wallet Operator → Hot Wallet Signer, in orange.

**Caption:** Route to a tier-0 asset

**Narration:**
> The access graph shows why this is urgent. Rahul's laptop session can act as Rahul, and an approved month end wallet grant already reaches the hot wallet signer, a tier zero asset.

### 1:44 · policy · 12s

**On screen:** the active policy rules in evaluation order (02 REJECT, 07 two security leads). Then the Independent Authority: members, a 2 of 2 quorum, and the signed bundle v1.1.0.

**Caption:** Signed by two independent leads

**Narration:**
> These rules are not a switch an attacker can flip. They live in a policy bundle signed by two independent security leads, and every decision names its rule.

### 1:56 · plan · 15s

**On screen:** incident `inc-2002`, then the containment plan for `user:rahul`:

- two actions: terminate the session, revoke Wallet Operator;
- 11 activities remain operational;
- only wallet signing is isolated.

**Caption:** Smallest cut · business keeps running

**Narration:**
> So Alice plans a containment. RATCHET searches for the smallest cut that removes every route to tier zero: end the laptop session and revoke the wallet role. Finance reports keep working for everyone, Rahul included.

### 2:11 · contain · 13s

**On screen:** "Execute containment" opens the labelled SIMULATED PASSKEY dialog. After "Use passkey", the incident reads CONTAINED and Rahul keeps only finance read access.

**Caption:** Passkey simulated in this demo

**Narration:**
> Alice confirms that exact plan with a passkey, which is simulated in this demo. Each action is recorded with its result, and the incident is marked as contained within seconds.

### 2:24 · audit · 12s

**On screen:** "Verify audit chain" shows "Chain integrity verified". Every event is re-hashed in the browser, and the end hash matches the server snapshot.

**Caption:** Tamper-evident · verified in your browser

**Narration:**
> Every step lands in a tamper evident ledger. One click recomputes every link of the hash chain right here in your browser, and the whole chain checks out.

### 2:36 · switch-role · 14s

**On screen:** "View as" switches to Rahul, and the same Audit page now says "Security lead access required". The cursor visits Guided tour and Reset.

**Caption:** Switch roles any time

**Narration:**
> Want a different view? Switch roles at any time from the top bar. As Rahul, the requester, the audit ledger is off limits. There is a guided tour and a reset button too.

### 2:50 · close · 10s

**On screen:** the end card (constructed, not product UI):

- the RATCHET wordmark and "Know what changes. *Before* it changes.";
- the demo URL;
- "Built for the DataNova 2026 Global Data-Thon";
- github.com/sakararya43-web/Ratchet.

**Caption:** sakararya43-web.github.io/Ratchet

**Narration:**
> Try it yourself at the link below. There is no sign up and nothing to install. RATCHET: know what changes, before it changes.

---

## 6. Capture notes

- **Deep links.** In demo mode, `#/console?as=alice&tab=incidents` signs in as that persona and opens that workspace directly, with no tour. Every console beat uses one, so a clip starts on the right screen instead of on a sign-in form. `as` takes `rahul`, `priya`, `alice` or `bob`. `tab` takes `overview`, `changes`, `infrastructure`, `impact`, `security-policy`, `incidents`, `audit` or `passkeys`.
- **Fresh state per beat.** Demo state lives in the browser tab, so each capture starts from the original Northwind data. That is why the contain beat recomputes the plan before executing it.
- **Trim the setup.** Clicks such as computing the plan in the contain beat are setup. Start the clip after them, or speed them up with `segments`.
- **Viewport.** Capture at 1600x900 (16:9) with `deviceScaleFactor` 2. The scroll offsets in the plan were measured at that size.
- **Relative times.** The site shows times such as "42m ago" relative to when the page opens. They read the same in every capture.

## 7. Rules

- **Say what is shown.** Every claim in the narration is visible in its beat. If a frame changes, change the line.
- **Fictional and simulated.** The organisation, people and records are fictional mock data, and the passkey prompt is simulated. Both are said out loud and visible on screen.
- **The Binance case.** The README cites it as the motivation. The video does not name it, and it never claims RATCHET would have prevented it.
- **No em dashes**, on screen or in narration.
