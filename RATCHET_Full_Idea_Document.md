# RATCHET
## Independent Security Control Plane for Preventing Privilege Escalation and Limiting Cyberattack Damage

**Concept document — non-technical edition**  
**Purpose:** Explain what RATCHET is, why it is needed, who it serves, how people use it, what it protects, and what value it is intended to deliver.  
**Scope:** Product idea and business concept only. This document intentionally does not describe the technical architecture, algorithms, software stack, data structures, integrations at an implementation level, or development instructions.

---

## 1. RATCHET in one sentence

**RATCHET is an independent security control system that prevents someone who has entered an organisation from quietly gaining more power, changing the rules that protect critical systems, or using one compromised account to reach the organisation’s most valuable assets.**

Its central belief is simple:

> **Getting inside an organisation should not mean gaining control of the organisation.**

RATCHET is designed for the moment when an attacker has already bypassed the organisation’s first line of defence. Rather than assuming every login is safe or that every internal request is legitimate, it focuses on controlling what an account, person or service is allowed to change after access has been obtained.

RATCHET is not an AI product. It does not depend on AI agents being present in an organisation. It is intended to protect traditional business systems, cloud environments, financial infrastructure and organisations that may also use AI-powered tools.

---

## 2. Executive summary

Organisations invest heavily in protecting their systems from unauthorised entry. They use identity checks, passwords, multi-factor authentication, access permissions, security monitoring and other safeguards. These protections are important, but they do not remove the risk that an attacker may eventually obtain a legitimate employee session, take control of a device, misuse a service account, or compromise an administrator.

Once inside, an attacker may try to do more than access information. They may attempt to:

- Give themselves or another account greater permissions.
- Create a new administrator or privileged account.
- Change who can approve important actions.
- Modify security settings or access rules.
- Create or expand access for service accounts and applications.
- Disable or weaken safeguards that would otherwise stop them.
- Gain access to financial systems, sensitive information or critical operations.
- Spread from one compromised part of the organisation into other systems.

RATCHET is designed to make those actions much harder.

It acts as an independent authority for sensitive changes. When someone requests an important increase in access or a change to a security control, RATCHET reviews what the change would allow. It considers which additional systems, information and critical assets could become reachable. It then permits the change, asks for separate approval, delays it for review, or blocks it according to the organisation’s rules.

RATCHET also follows an important operating principle: **reducing access should be easier and faster than increasing access.** During a suspected compromise, the organisation should be able to revoke a risky permission, disable a compromised account or restrict a dangerous capability quickly. By contrast, granting powerful new access or changing critical security protections should require stronger scrutiny.

If an incident occurs, RATCHET aims to help the organisation contain the affected access without unnecessarily shutting down unrelated business activity.

The product is therefore about protecting the organisation’s authority and control—not merely showing alerts about suspicious activity.

---

## 3. The problem RATCHET addresses

### 3.1 The gap between entering a system and controlling it

A person who gets into an organisation does not automatically have access to everything. However, attackers often try to expand the access they already have. They may use a compromised employee account, misuse an existing service account, or exploit an authorised person's ability to make changes.

A security system may correctly recognise that an account has logged in with valid credentials, while still failing to recognise that the account is now being used to request an unsafe increase in authority.

For example, an employee may normally be allowed to view financial reports. If that employee's account is stolen, an attacker could attempt to turn the account into an administrator, give it access to a payment system, or change who is allowed to approve withdrawals.

The danger is not limited to the initial account compromise. The greater danger is what the attacker can make possible next.

### 3.2 Security controls can become targets

An attacker may try to weaken the very protections designed to stop them. Examples include changing security policies, adding an unauthorised administrator, changing approval requirements, or reducing the visibility of important activity.

If the same compromised account or management process can freely change the safeguards that govern it, the organisation may lose control over its own protection.

RATCHET addresses this by treating important security controls as assets that need their own protection and independent oversight.

### 3.3 Small changes can create large consequences

A permission change can look minor when viewed by itself. Giving a person access to one additional service, creating one new account, or changing one approval role may appear routine. But that change may create a path to sensitive information, production systems, financial infrastructure or other powerful accounts.

RATCHET is concerned with the consequence of the change, not just the name of the permission being requested.

### 3.4 One compromised account should not expose the whole organisation

Organisations need to limit how far an attacker can move and how much damage one compromised identity can cause. RATCHET aims to prevent an ordinary account from becoming a route to critical assets and to make it possible to contain compromised access without disabling every user or service.

---

## 4. The central idea

RATCHET introduces an independent security authority that reviews sensitive changes before they take effect.

It asks four plain-language questions:

1. **Who is requesting this change?** Is the request coming from the person or service that should be making it?
2. **What new power will this change create?** What will the requester be able to access, change, approve or control afterward?
3. **What could the change put at risk?** Could it create a path to critical systems, valuable assets, sensitive information or security controls?
4. **Should this change be allowed?** Is it appropriate, properly approved and consistent with the organisation’s security rules?

The important difference is that RATCHET considers the situation that would exist *after* a proposed change, before the organisation accepts that change.

It is not enough to ask whether a user is allowed to submit a request. RATCHET asks whether the result of approving that request is safe and justified.

---

## 5. What RATCHET is—and what it is not

### RATCHET is:

- An independent security authority for important access and security changes.
- A safeguard against unauthorised increases in privilege.
- A way to review the potential consequences of a proposed change before it is accepted.
- A means of protecting critical security rules from unauthorised alteration.
- A way to reduce the damage that can follow a compromised account or service.
- A tool for security teams to review, approve, reject and contain sensitive changes.
- A product intended to preserve legitimate business operations while restricting compromised access.

### RATCHET is not:

- A general-purpose AI chatbot.
- A screen that only displays security statistics or threat scores.
- A replacement for every existing security product in an organisation.
- A tool whose main purpose is to identify malicious prompts.
- A transaction-monitoring product focused only on detecting fraudulent payments.
- A guarantee that an organisation can never be breached.
- A reason to give security teams unlimited access to employee or customer information.
- A system that should automatically approve every request or automatically block every unusual request without context.

RATCHET focuses on preventing dangerous changes to authority and limiting what compromised access can achieve. It complements other security controls rather than claiming to replace all of them.

---

## 6. Who RATCHET is for

### 6.1 Primary organisations

RATCHET is most relevant to organisations where a small number of accounts, permissions or configuration changes can create significant financial, operational or information-security consequences.

Potential initial customers include:

- Cryptocurrency exchanges and digital-asset businesses.
- Banks and financial institutions.
- Fintech and payment companies.
- Cloud and infrastructure service providers.
- Large enterprises with complex employee and service access.
- Organisations operating sensitive customer databases or important production systems.
- Critical-service organisations where unauthorised changes could disrupt essential operations.

The most suitable initial focus for the first product demonstration is a cryptocurrency exchange or financial institution. These organisations provide an easy-to-understand example of why control over privileged access and security settings matters. The product itself is not limited to the financial sector.

### 6.2 People who use or benefit from RATCHET

**Chief Information Security Officer (CISO)**  
Responsible for the organisation’s overall security posture. The CISO uses RATCHET to establish how critical access changes are governed and to ensure that compromised accounts cannot easily gain control over sensitive systems.

**Security operations team**  
Reviews suspicious changes, investigates incidents, decides whether access should be restricted and coordinates the response to potential compromise.

**Identity and access management team**  
Manages employee, administrator and service permissions. RATCHET gives this team a clearer way to review the consequences of powerful access changes.

**Cloud, infrastructure and DevOps teams**  
Request and manage changes that affect important environments. RATCHET helps ensure that routine work does not accidentally or improperly create dangerous access.

**Business or system owner**  
Understands why a person or service needs access to a particular business resource. This person can confirm whether a requested change has a legitimate business reason.

**Independent approver**  
Reviews especially sensitive changes separately from the person requesting them. This helps prevent one compromised account from both requesting and approving its own increase in authority.

**Auditors and risk teams**  
Review who requested important changes, who approved them, what was allowed or rejected, and how the organisation responded to incidents.

**Employees and service owners**  
Benefit from clearer access decisions and from security controls that aim to restrict compromised accounts without unnecessarily interrupting normal work.

---

## 7. The main product principles

RATCHET should be guided by the following principles in every part of the product.

### 7.1 Independent protection

The security rules that protect an organisation should not depend entirely on the same account or administrative process that those rules are meant to control. Important changes must be reviewed by an authority that is independently governed.

### 7.2 Prevention before impact

RATCHET should review high-impact changes before they take effect. An alert received after a dangerous change has already been applied may be too late to prevent the new access from being used.

### 7.3 Understand consequences, not just permissions

A permission should not be judged only by its label. RATCHET should help the organisation understand what the person or service could actually reach or control after the change.

### 7.4 Least privilege

People and services should receive only the access needed for their responsibilities. Powerful access should not be permanent by default.

### 7.5 Asymmetric permission rule

Reducing access should be fast when there is a credible security concern. Increasing access, especially access to critical resources, should require more scrutiny and appropriate approval.

### 7.6 Minimum disruption

When access is compromised, the response should focus on restricting the affected identity, permission or route. The organisation should avoid shutting down unrelated work when it is safe to preserve it.

### 7.7 Clear accountability

Important security decisions should have an understandable reason and an accountable owner. Users should be able to see why a change was delayed, approved or rejected.

### 7.8 Human responsibility for exceptional decisions

RATCHET should not remove human accountability from important business and security decisions. It should help authorised people make better-informed decisions and apply agreed emergency rules consistently.

### 7.9 Privacy and proportionality

Security oversight should collect and expose only information needed for legitimate protection and investigation. RATCHET should not become a general employee-surveillance product.

---

## 8. The four core capabilities

### 8.1 Independent Security Authority

RATCHET maintains a separately governed authority for the organisation’s most sensitive security decisions.

This authority protects important rules such as:

- Who may create or promote an administrator.
- Who may change access to critical systems.
- Who may change financial or operational approval rules.
- Who may weaken, disable or replace security safeguards.
- Which changes require a second person or a separate approval.
- Which emergency actions may be taken immediately.

The purpose is to prevent a compromised production account from freely rewriting the protections that are supposed to constrain it.

This independent authority should have clear ownership, restricted administration and its own review process. It must not become an unchecked power belonging to one individual or team.

### 8.2 Permission Change Review

Every important request to increase or alter access is treated as a decision that deserves review.

Examples include:

- Giving an employee administrator privileges.
- Creating a new privileged account.
- Allowing a service to access sensitive information.
- Giving an application access to a financial system.
- Changing who can approve a payment or withdrawal.
- Increasing the authority of an existing account.
- Changing access to critical production environments.

RATCHET presents the request in understandable terms: who is asking, what they currently have, what they want, why they need it and what the change would enable.

A request can be:

- **Allowed:** The change is appropriate and meets the organisation’s rules.
- **Sent for independent approval:** The change may be legitimate but is too sensitive for the requester to approve alone.
- **Held for review:** More context is needed before a decision can be made.
- **Rejected:** The change is not allowed or creates an unacceptable risk.

### 8.3 Impact and Blast-Radius Review

Before a sensitive change is accepted, RATCHET helps the reviewer understand its possible consequences.

It should make clear:

- Which additional systems or resources become accessible.
- Whether the change creates a new route to sensitive or critical assets.
- Whether the person or service could gain control over other accounts.
- Whether the change would weaken an existing safeguard.
- Whether the change creates a larger potential area of damage if the account is compromised.
- Whether the requested access is broader than the stated business need.

This is the product’s central review experience. A reviewer should not need to guess what a powerful permission means. RATCHET should explain the practical effect in terms that security, business and infrastructure owners can understand.

The term **blast radius** refers to how much of the organisation could be affected if a particular account, service or permission were misused.

### 8.4 Emergency Containment

If an account, service or permission is believed to be compromised, RATCHET helps the organisation reduce the danger quickly.

Possible actions include:

- Restricting a compromised account.
- Ending a suspicious session.
- Removing a newly granted privilege.
- Disabling a risky service permission.
- Preventing a sensitive change from taking effect.
- Temporarily restricting access to a critical resource.
- Keeping unrelated, safe business activities available where possible.

Emergency actions should be fast but accountable. RATCHET should record who initiated the response, what was restricted, why it was necessary and what needs to happen before normal access is restored.

---

## 9. The asymmetric permission principle

This is one of RATCHET’s defining product rules.

**Taking power away should be easier than giving more power.**

An attacker who has entered an organisation should not be able to quickly expand their authority. At the same time, the organisation must be able to remove dangerous access quickly when a compromise is suspected.

| Type of change | RATCHET’s intended treatment | Example |
|---|---|---|
| Reduce access | Fast, according to emergency and security rules | Disable a compromised account’s administrative access |
| Revoke a session | Fast when a compromise is suspected | End a stolen or suspicious employee session |
| Remove a risky permission | Fast and targeted | Remove access to a sensitive payment service |
| Add ordinary access | Normal review based on the organisation’s policy | Give an employee access to a report needed for their job |
| Add privileged access | Stronger review and appropriate approval | Give an employee administrator privileges |
| Change critical security rules | Independent review and approval | Change who can authorise large withdrawals |
| Weaken or disable safeguards | Exceptional treatment, with strong restrictions | Attempt to turn off an important security requirement |

The principle does not mean that every permission increase is automatically malicious. Organisations need to make legitimate changes every day. RATCHET’s purpose is to make sure that the importance of a change determines the level of review it receives.

---

## 10. A complete real-world example

### Scenario: A stolen employee account at a cryptocurrency exchange

A cryptocurrency exchange holds a large amount of customer and company digital assets. An employee named Rahul works in the finance department. Rahul can view financial reports, but he is not allowed to control wallet withdrawals or change security policies.

An attacker steals Rahul’s account access.

#### What the attacker tries to do

1. The attacker enters the company using Rahul’s compromised account.
2. The attacker tries to give Rahul administrator privileges.
3. The attacker attempts to obtain access to the wallet-signing area.
4. The attacker attempts to change the rules governing withdrawals.
5. The attacker plans to move company assets to an unauthorised destination.

#### What RATCHET does

**First: It recognises that a sensitive change is being requested.**  
The request to make Rahul an administrator is not treated as an ordinary access request. It is placed under review.

**Second: It examines what the proposed change would allow.**  
RATCHET shows that the new role would create access to wallet infrastructure and important security controls. This is substantially more authority than Rahul needs for his finance-reporting responsibilities.

**Third: It refuses to let the compromised account approve its own increase in power.**  
The request is rejected or sent for approval through a separate, trusted process, according to the organisation’s policy.

**Fourth: It protects the security rules.**  
When the attacker attempts to change withdrawal safeguards or approval requirements, RATCHET requires independent authority. The compromised production account cannot simply rewrite those protections.

**Fifth: It supports containment.**  
Once the compromise is confirmed, the security team restricts Rahul’s affected access and removes the risky permissions. Unrelated finance activities may continue if they are safe to preserve.

#### Intended result

The attacker may have entered the organisation, but the stolen account does not automatically become an administrator, gain wallet control or acquire the ability to rewrite the organisation’s security rules.

This example demonstrates RATCHET’s purpose: **limit what a compromised identity can become capable of doing.**

---

## 11. Other situations RATCHET should address

RATCHET is designed to protect more than cryptocurrency wallets. The same problem appears wherever access changes can expose important systems or allow one account to gain excessive control.

### 11.1 A developer’s account is compromised

An attacker gets access to a developer’s account and tries to gain control over important production environments. RATCHET reviews the requested increase in access and prevents the account from being promoted into a role that provides more authority than the developer needs.

### 11.2 A new administrator is created unexpectedly

An attacker or unauthorised insider attempts to create a new high-privilege account. RATCHET treats the creation as a sensitive change, checks its justification and requires the organisation’s independent approval process.

### 11.3 A service account is given excessive access

A business application needs limited access to perform a specific task. Someone requests broad access to multiple confidential systems. RATCHET highlights the extra access and allows the organisation to restrict the request to what the application actually needs.

### 11.4 Security protections are weakened

Someone tries to remove an approval requirement, change a security rule or weaken a critical safeguard. RATCHET protects these changes from being made by an account that is not independently authorised to do so.

### 11.5 A compromised account is used to spread

An attacker tries to use one compromised identity to gain access to other accounts and systems. RATCHET helps the organisation understand the additional access being requested and restricts the dangerous expansion.

### 11.6 A legitimate employee needs emergency access

An employee may genuinely need temporary access to restore an important service. RATCHET should support a controlled emergency process rather than permanently blocking the work. The access should be limited to the emergency need, properly approved and reviewed afterward.

---

## 12. How a normal RATCHET user journey works

RATCHET should operate in the background for routine activity. Users should not need to watch a screen continuously. The product should bring people into the process when a sensitive decision, review or emergency action is needed.

### Journey A: A normal access request

1. An employee asks for access required for their job.
2. The request explains what access is needed and why.
3. RATCHET checks the request against the organisation’s access rules.
4. If the request is ordinary and appropriate, it follows the normal approval process.
5. The employee receives a clear decision and knows what access has been granted.

### Journey B: A sensitive privilege request

1. An employee or service requests powerful new access.
2. RATCHET places the request in the change-review area.
3. The reviewer sees the current access and the proposed access.
4. RATCHET explains which additional systems and resources would become reachable.
5. The reviewer approves, rejects or asks for independent approval.
6. The decision and its reason are recorded.

### Journey C: A dangerous change is requested

1. A request would expose critical assets or weaken an important safeguard.
2. RATCHET highlights the potential consequence.
3. The request is blocked or held under the organisation’s policy.
4. The responsible security team is notified.
5. The organisation investigates whether the request was mistaken, unauthorised or part of an attack.

### Journey D: An account is believed to be compromised

1. The security team identifies a suspected compromise.
2. RATCHET presents the affected account and the important permissions associated with it.
3. The authorised responder chooses the appropriate containment action or uses an established emergency rule.
4. The affected access is restricted.
5. Unrelated business activities are preserved where safe.
6. The incident is documented and reviewed before normal access is restored.

### Journey E: An employee needs legitimate emergency access

1. An employee explains the urgent business need.
2. The request is marked as exceptional and time-sensitive.
3. The appropriate independent approver reviews the request.
4. Only the necessary access is granted for the required period.
5. The access is reviewed and removed when the emergency ends.

---

## 13. The RATCHET product experience

RATCHET should feel like a professional security-control product, not a generic analytics dashboard. Its interface should help users understand the organisation, review important changes and take clear actions.

The first version should focus on a small number of strong, useful screens rather than a large collection of statistics.

### 13.1 Security Overview

The starting point for a security administrator. It should show the current state of important security decisions, including:

- Sensitive changes awaiting review.
- Recently approved and rejected changes.
- Important security-policy changes.
- Active incidents that need attention.
- Access that has recently been restricted.
- Critical areas that require a review.

The overview should prioritise decisions and work requiring attention. It should not be dominated by decorative numbers or generic risk charts.

### 13.2 Infrastructure Map

A visual map of the organisation’s important people, accounts, services and resources and how they are connected.

A user should be able to select an employee, administrator, service or important resource and understand:

- What it can access.
- Who or what granted that access.
- Which other areas it can influence.
- Whether it has access to critical resources.
- What a proposed change would add or remove.

The map should make complicated relationships understandable, not overwhelm users with every detail at once.

### 13.3 Change Review

The main working area of RATCHET.

Each request should clearly show:

- Who is requesting the change.
- What they currently have permission to do.
- What they want to be allowed to do.
- Why they say the change is needed.
- Which resources or responsibilities would be affected.
- What additional power the change would create.
- Which approvals are required.
- What decision has been made and why.

The reviewer should be able to approve, reject, hold or request more information, depending on their authority and the organisation’s rules.

### 13.4 Impact Simulator

This area helps the reviewer understand the consequences of a proposed change before accepting it.

It should provide a clear comparison between the organisation’s current state and the state that would exist after the requested change.

The focus should be on practical questions:

- What becomes newly accessible?
- What becomes newly controllable?
- Does the change create a route to a critical resource?
- Does it weaken a safeguard?
- How much could be affected if the account were misused?

### 13.5 Security Policy Area

A restricted area where authorised security leaders manage the organisation’s rules for sensitive changes.

It should let the organisation define:

- Which changes are considered sensitive.
- Which roles may request them.
- Which roles may approve them.
- Which changes need more than one independent approval.
- Which safeguards cannot be weakened through normal requests.
- Which emergency actions can be taken quickly.
- How temporary access is reviewed and removed.

Changes to these rules must themselves receive special protection and review.

### 13.6 Incident Containment

An operational area for responding to a suspected or confirmed compromise.

It should present:

- The suspected affected account or service.
- The access and resources associated with it.
- The actions that can be restricted.
- The business activities that may be affected.
- The containment decisions already taken.
- The steps needed to investigate and restore normal access.

The screen should help the responder act deliberately and avoid broad shutdowns where a narrower response is safe.

### 13.7 Audit and History

A clear record of important activity, including:

- Who requested a change.
- Who reviewed and approved or rejected it.
- What the change would have allowed.
- Why the decision was made.
- When the change took effect, if approved.
- What emergency actions were taken.
- When access was restored or permanently removed.

This record supports accountability, internal review, investigations and external audits.

---

## 14. How decisions should be made

RATCHET should use clear decision categories so users understand what is happening and what they need to do.

### Allow

The request is appropriate, justified and within the organisation’s rules. It can proceed through the normal process.

### Require independent approval

The request may be legitimate, but it is powerful enough that the requester should not be able to approve it alone. A separate authorised person or group must review it.

### Hold for review

The request is not necessarily malicious, but there is not enough information to make a safe decision. The organisation must obtain context before proceeding.

### Reject

The request violates a rule, creates unacceptable exposure, or lacks the necessary authority. It must not take effect.

### Restrict or revoke

A permission, account or session should be limited or removed because it is believed to be compromised or unsafe.

Every decision should be understandable and recorded. When a request is rejected, the requester should receive an appropriate explanation without revealing sensitive security details to someone who should not see them.

---

## 15. Governance and accountability

RATCHET itself must be governed carefully. A product designed to protect an organisation’s authority must not become an uncontrolled authority of its own.

### 15.1 Separate responsibilities

The person requesting a powerful change should not automatically be the only person who approves it. The organisation should define separate responsibilities for requesting, reviewing, approving and auditing sensitive changes.

### 15.2 Independent oversight

The most important security rules should be overseen by designated security leadership and should not be casually changed by ordinary production administrators.

### 15.3 Emergency access

Organisations need an emergency process for situations where an important service must be restored quickly. Emergency access should be limited, time-bound, accountable and reviewed afterward. It should not become a permanent shortcut around normal controls.

### 15.4 Avoiding misuse by insiders

RATCHET should also protect against abuse by authorised employees. Its records and approval practices should make it difficult for one insider to quietly grant excessive access, change important rules or conceal a sensitive decision.

### 15.5 Regular review

Organisations should periodically review powerful accounts, exceptional permissions, temporary access, unused privileges and the rules governing security changes.

---

## 16. Privacy and responsible use

RATCHET will deal with information about employees, accounts, devices, business activity and important systems. Its use must be proportionate and transparent.

The product should follow these principles:

- **Collect only what is necessary:** Focus on information relevant to access decisions, security changes and incident response.
- **Limit who can see sensitive information:** Not every administrator needs access to every employee or customer detail.
- **Use information for defined security purposes:** RATCHET should not become a general employee-performance monitoring tool.
- **Protect investigation records:** Sensitive incident information should be available only to people with a legitimate responsibility.
- **Set clear retention rules:** Information should not be kept indefinitely without a valid reason.
- **Support accountability:** Important decisions and access to sensitive records should themselves be reviewable.
- **Respect legitimate work:** An unusual request should not automatically be treated as proof of wrongdoing. People need a fair process to clarify legitimate business needs.

RATCHET should protect the organisation without treating every employee as a suspect.

---

## 17. Business value

### 17.1 Reduce the impact of compromised accounts

A stolen employee or service account should not automatically become a path to critical systems. RATCHET is intended to restrict the opportunities available to an attacker after an initial compromise.

### 17.2 Protect critical security settings

By protecting the rules that govern privileged changes, RATCHET helps reduce the chance that an attacker can weaken the organisation’s safeguards from inside the environment.

### 17.3 Reduce the risk of major financial and operational losses

Preventing unauthorised access to sensitive systems can reduce the possibility of financial theft, data exposure, service disruption and expensive recovery efforts.

### 17.4 Reduce unnecessary business disruption

Targeted containment can help an organisation restrict the affected account or capability rather than immediately disabling broad groups of users or services.

### 17.5 Improve accountability

A clear record of important access changes and decisions helps security teams, business owners and auditors understand how authority is granted and controlled.

### 17.6 Improve confidence in privileged access

Organisations can have greater confidence that powerful access is justified, reviewed and limited to the needs of the role or task.

---

## 18. What makes RATCHET distinct

RATCHET’s value is not based on claiming that access control, security monitoring or approval processes are new. Organisations already use many forms of these protections.

The product’s intended distinction is the way it brings several concerns together around one question:

**What new power does this change create, and is the organisation prepared to accept the consequences?**

RATCHET brings together:

1. Independent protection for important security rules.
2. Review of powerful permission and configuration changes before they take effect.
3. A clear view of what new access or control a change would create.
4. Faster reduction of permissions than expansion of permissions.
5. Targeted containment when an account or service is compromised.
6. Accountability for every important decision.

Many security tools focus on identifying suspicious activity, managing identities, or protecting individual systems. RATCHET’s product focus is the control of authority changes across the organisation and the potential consequences of those changes.

Its differentiation must ultimately be demonstrated through a working product and fair comparisons with existing security controls. The concept should not claim that no other organisation has ever built a similar feature.

---

## 19. Intended first version of the product

The first version should be narrow enough to demonstrate clearly, but complete enough to prove the central idea.

### Initial environment

A simulated cryptocurrency exchange or financial company with:

- Employees with different responsibilities.
- A small group of administrators.
- Sensitive financial and customer resources.
- Service accounts used by business applications.
- Important security policies.
- A clear separation between ordinary access and critical access.

### The first version must demonstrate

1. A normal employee can request ordinary access.
2. A request for administrator privileges is treated as a sensitive change.
3. RATCHET shows what additional resources the new role would expose.
4. A compromised employee cannot approve their own privilege increase.
5. An attempt to change a critical security rule receives independent review or is rejected.
6. A security responder can revoke compromised access.
7. Unrelated safe activities can continue where possible.
8. Every important decision is recorded and can be reviewed.

### What the first version should not attempt to cover

- Every possible type of cyberattack.
- Every industry and every kind of infrastructure at once.
- Full replacement of an organisation’s existing identity and security products.
- A general-purpose fraud-monitoring platform.
- A broad AI security product.
- A complete financial transaction approval and payment management system.
- A promise that no breach can ever happen.

The initial product should prove one strong proposition: **a compromised account cannot freely expand its authority or rewrite the security controls that restrict it.**

---

## 20. How RATCHET should grow

### Stage 1: Prove the central security idea

Focus on employee accounts, administrator privileges, sensitive permission changes and protection of critical security rules. Demonstrate the complete journey from a requested change to impact review, decision and containment.

### Stage 2: Broaden the organisation’s coverage

Extend the product’s coverage to more types of business services, applications, service accounts, cloud environments and important information resources. Improve how organisations review the combined impact of changes across different departments.

### Stage 3: Support wider enterprise operations

Help larger organisations apply consistent rules to sensitive access changes across many business units and environments. Provide more mature review, exception, emergency and audit processes.

### Stage 4: Expand into additional industries

Adapt the product for banks, fintech companies, cloud providers, large enterprises and critical-service organisations while retaining the same central principle: powerful changes should be reviewed according to the authority and consequences they create.

This is a product direction, not a promise that every stage will be delivered in a particular timeframe.

---

## 21. How success should be measured

RATCHET should be judged by whether it makes an organisation harder to take over and easier to protect—not by the number of alerts it displays.

Useful measures include:

- How many unauthorised privilege increases are prevented.
- How many dangerous security-policy changes are stopped before they take effect.
- How often legitimate access requests are incorrectly delayed or rejected.
- How much critical access can be reached from a compromised ordinary account before and after RATCHET is introduced.
- How quickly a compromised permission can be restricted.
- How much unrelated business activity remains available during containment.
- How clearly users and reviewers understand why a change was allowed or rejected.
- How completely the organisation can explain who requested, approved and carried out a sensitive change.

The product should be evaluated against realistic attack scenarios and normal business activity. It should not claim success based only on simulated examples that it was specifically programmed to block.

---

## 22. Risks, limitations and honest expectations

RATCHET is intended to reduce the ability of an attacker to expand control after entering an organisation. It does not eliminate every route into an organisation and should not be presented as a universal guarantee against cyberattacks.

Important limitations and risks include:

### 22.1 Incomplete coverage

If an important system can be changed without passing through the organisation’s defined review and control process, an attacker may be able to bypass RATCHET. The organisation must identify and protect the important routes through which critical changes can occur.

### 22.2 Compromise of the independent authority

If an attacker gains control over the independent security authority itself, the protection may be weakened. Its independence, oversight and recovery arrangements are therefore essential.

### 22.3 Incorrect decisions

A legitimate change may look unusual, while a harmful change may appear routine. RATCHET needs clear policies, useful context, human review for exceptional cases and regular evaluation to avoid unnecessary disruption.

### 22.4 Business delays

Strong approval requirements can slow down legitimate work. Rules must be proportionate to the importance of the resource and must support genuine emergencies.

### 22.5 Insider misuse

A person with legitimate authority may still misuse it. Independent review, accountability and clear separation of responsibilities remain important.

### 22.6 Overly broad restrictions

Blocking too much access can disrupt the organisation. RATCHET should aim for targeted restrictions and preserve safe business activity wherever possible.

### 22.7 No substitute for sound security practices

RATCHET does not remove the need for good identity protection, secure devices, sound employee practices, incident response, backups and other established safeguards.

The product should be positioned as an additional layer of protection focused on authority, sensitive changes and damage limitation.

---

## 23. The product’s personality and user experience

RATCHET should feel serious, precise, dependable and operational.

It should not feel like a chatbot or a consumer productivity application.

Its interface should communicate:

- **Control:** Users can see what is happening and what decision is needed.
- **Clarity:** The impact of a change is explained in ordinary language.
- **Evidence:** Important decisions are supported by visible reasons.
- **Restraint:** The product does not interrupt routine work unnecessarily.
- **Authority:** Sensitive actions are governed by clearly defined responsibilities.
- **Accountability:** Every important decision has a record and an owner.
- **Continuity:** The goal is to stop the dangerous activity while keeping safe work running.

The key experience is not a screen full of threat statistics. It is a reviewer opening a sensitive change, understanding what power it would grant, seeing what could become exposed, and making a justified decision before the change happens.

---

## 24. Positioning statement

**RATCHET is an independent security control platform that protects organisations from attackers who try to turn compromised access into greater authority. It reviews powerful changes before they take effect, protects critical security rules from unauthorised modification, and helps contain compromised access without unnecessarily stopping legitimate business operations.**

### Short pitch

Most security systems focus on keeping attackers out or detecting suspicious activity. RATCHET focuses on what happens after an attacker gets in. It prevents compromised accounts from promoting themselves, changing the security rules or gaining access to critical infrastructure. It evaluates the consequences of powerful changes before they are approved and helps organisations remove compromised access quickly while preserving safe operations.

### One-line pitch

> **RATCHET: Entering the system should never mean gaining control of the system.**

---

## 25. Final understanding: What are we building?

We are building a security product that stands guard over the organisation’s most powerful permissions and security settings.

When someone asks for more access, RATCHET checks what that access would actually allow. When someone tries to change an important security rule, RATCHET ensures that the change receives the independent authority it requires. When an account is compromised, RATCHET helps remove the dangerous access without unnecessarily disabling the rest of the organisation.

The product is built around one central idea:

**An attacker may succeed in entering an organisation, but they should not be able to turn that entry into unlimited authority.**

That is RATCHET.

---

*End of non-technical concept document.*
