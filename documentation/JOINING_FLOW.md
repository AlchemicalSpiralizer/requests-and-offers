# The joining flow, end to end

This is the canonical run-through of how someone joins R&O — the whole journey, start to finish, that the implementation issues are accountable to. The chunked issues (below) say *what to build, in what order*; this says *what the experience is*, so the pieces stay coherent as they're built separately.

It's the design spec. The clickable reference is the prototype on `feat/joining-flow-app-mode` (design-system repo) — open `/ui-kit/app` and follow it through. For the membrane's internal mechanics — the decline catalogue, the scaffold/versioning model, the warm-invite model — see `MEMBRANE_MANAGEMENT.md`; this doc is the spine those hang off.

## Two ways in

- **The open applicant (cold path)** — someone arrives unprompted, applies, verifies their email, and waits for a human to decide. The default posture is trust and welcome; the absence of a prior connection is never a "no."
- **The invited member (warm path)** — an admin who already knows someone issues an invitation ahead of their arrival. Issuing the invite *is* the admission decision, made in advance; when they arrive, R&O vouches for their agent automatically. (Admit-on-arrival — see `MEMBRANE_MANAGEMENT.md` and #168.)

Both paths surface in the same one queue for the admin, and both end at the same welcomed-in state.

## The mechanism underneath (Option B*, #165)

Every join is gated — no open DHT. The joining service runs two auth methods in sequence: `email_code` (the applicant verifies their email) then `delegated_verification` (R&O vouches for the specific agent once an admin approves). R&O owns the admission decision in its own app; the vouch binds to one agent key, not a transferable token. The Path B membrane-proof gate is unchanged. The flow below is the human face of that mechanism.

## The journey, screen by screen

*(Route keys are the prototype's; the prototype's guard is the detailed reference for the exact transitions.)*

**1. Arrival**
- Cold: **`join-welcome`** — what R&O is, the invitation to join, a single CTA to start.
- Warm: **`invite-landing`** — the invited person arrives via their link and is greeted by name; their path is already an admit.

**2. The application — `join-form`** *(cold path)*
Name (with a mononym option), nickname, advocate/creator, email, and the optional "what brings you here?". On submit, the guard seeds the two challenges — `email_code`, then `delegated_verification` — and moves to email verification.

**3. Email verification — `join-verify-email`** *(cold path)*
Enter the 6-digit code sent to the email; resend; "used the wrong email?" back to the form. This is the `email_code` step made visible. A valid code → pending.

**4. Pending — `join-pending`**
The application is in. A person will read it — not an algorithm, and not instantly. Sets that expectation without promising a timeline.

**5. The membrane decision** *(the admin's path crosses here — see The membrane, below)*
An admin reads the application and makes a signed, reasoned decision: welcome them in, or decline. For an invited applicant there's no decision to make — only a confirm-and-welcome, since the call was made at issuance.

**6a. Approved — `join-approved` → `home`**
Welcomed in. The home getting-started card carries the first three actions — finish your profile, post an offer or request, find someone — with progress and a Skip.

**6b. Declined — `join-rejected`**
Two tiers. The reengagement tier (*not currently accepting*, *not yet connected*, *out of scope*) is warm and always points to a real path back — a reopen-notify opt-in, a recourse email, a "we don't know each other yet, here's how we could." The hard refusal (*safety*) is final, with no path back. The wording lives in the decline catalogue.

## The membrane (the admin's side)

**The queue — `admin-membrane`.** One queue, no green/rest split. An oldest/newest sort, default oldest-first, so the longest wait is seen first. Signals enquire, never refuse: green = a corroborated connection (an invite or a vouch), red = a safety flag to read urgently, no mark = the warm default, read in full. No automated rejection exists.

**The decision — `admin-membrane-review`.** The admin opens the application: the claims, the "what brings you here?", and any deterministic notes shown *inside the read*, never as a queue badge. Then:
- **Welcome** (invited) — no decline path; the admit was made at issuance.
- **Accept** (cold) — admits and vouches the agent.
- **Decline** — opens the reason catalogue, requires linking evidence before it commits, and the admin authors the outbound message themselves. The internal record and the message to the applicant stay separate.

Full membrane design — the catalogue, the activity mask, versioning, the warm-invite model — is in `MEMBRANE_MANAGEMENT.md` (#166).

## Lifecycle states (beyond the first join)

- **`password-gate` / `join-set-password`** — access for a returning member.
- **`member-suspended`** — a suspended member's view: a door, not a wall.
- **`rules-reattestation`** — when the Community Agreement is re-versioned, members re-attest to the current version (the rules-stale flow; #166).
- Connection and gating states — **`connecting`**, **`access-issue`**, **`profile-guard`**.

## What's real, and what isn't (in the prototype)

The prototype validates the *experience*; it isn't the implementation. Real and portable: the screen structure, the copy, the Skeleton styling, and `decline-catalogue.ts` (real content). Mock: the data, the deterministic signal checks (stubs, no semantic enrichment), a `route` state variable in place of routing, and a mock guard. The admin **issuance** side — creating an invite — isn't built; only the invited applicant's arrival is.

## How this decomposes (the build, once agreed)

The flow maps onto the existing issues — it isn't a monolith:
- **#165** — the joining mechanism (the two auth methods, R&O's vouch, the connect pre-step).
- **#166** — the membrane decision (the queue, the decide screen, the soft-membrane posture and catalogue).
- **#168** — the warm-invite tooling (issuance + the invited ledger).
- **#95** — the member-facing onboarding UX (welcome → form → verify → pending → approved), or a fresh implementation issue if that's cleaner.

This doc is what each of those checks itself against. Build order and timeline come next, once there's a go-ahead.

## References

- Clickable prototype: `feat/joining-flow-app-mode` (design-system repo) → `/ui-kit/app`
- Membrane internals: `MEMBRANE_MANAGEMENT.md`
- Mechanism #165 (Option B*) · Membrane #166 · Invites #168 · Onboarding UX #95
