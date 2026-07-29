# Conversation DNA — Data Model

**Status:** Draft, written before scaffolding
**Governed by:** `documentation/architecture/chat-system.md` (design of record). This note
adds the entry, link and validation detail for build sequence step three. Where the two
disagree, the design note wins and this one is wrong.
**Stack:** hdi =0.7.1 / hdk =0.6.1

## 1. Scope

One DNA, cloned once per conversation. The clone is the conversation, so nothing here
identifies which conversation an entry belongs to: the DHT boundary already does that.

## 2. Zome pair

`conversation_integrity` and `conversation`. The existing `messaging` coordinator zome
from #181 is referenced unchanged as a second zome in this DNA, giving in-conversation
liveness. It is DNA-agnostic: no entry types, no integrity pair, no DNA property reads.

## 3. DNA properties

    pub struct Properties {
        pub progenitor_pubkey: Option<String>,
        pub conversation_id: String,
    }

`progenitor_pubkey` follows R&O's existing convention in `utils/src/dna_properties.rs`:
base64 `u`-prefixed, 39 raw bytes, `Option` so dev mode stays permissive.

The progenitor is the conversation's creator, not the network progenitor. Properties are
supplied per clone at creation, so each conversation has its own root of trust and the
creator admits its participants.

`conversation_id` is a random opaque identifier, bound into the membrane proof so a proof
for one conversation cannot admit its holder to another. It must not be derived from the
network seed, which stays secret.

## 4. Membrane proof

    pub struct MembraneProofPayload {
        pub conversation_id: String,
        pub target_agent: AgentPubKey,
        pub issued_at: Timestamp,
    }

    pub struct MembraneProofData {
        pub payload: MembraneProofPayload,
        pub creator_signature: Signature,
    }

Signature is over the raw encoded payload bytes. Verified with `verify_signature_raw`,
NOT `verify_signature`, which serialises its input first and will fail against a raw
signature. This cost real time in Fieldnotes; see `parse_progenitor_pubkey` and
`validate_admin_grant` in the Fieldnotes integrity zome for the working precedent.

Binding both `conversation_id` and `target_agent` is what stops a proof being replayed
into another clone or handed to a third party.

## 5. Entry types

    Entry: ConversationConfig                                    Visibility: Public
      participants: Vec<AgentPubKey>
      context_hash: Option<ActionHash>      listing this concerns, on the shared DNA
      context_type: Option<ContextType>     Request | Offer | Organization | Direct
      title: Option<String>
      created_at: Timestamp

    Entry: Message                                               Visibility: Public
      content: String
      message_type: MessageType             Text | System
      reply_to: Option<ActionHash>
      created_at: Timestamp

Content is plaintext. A clone contains exactly its participants, who hold the plaintext by
definition, and this follows Volla, whose conversation zomes contain no content encryption.

`context_hash` is a stored identifier, not a DHT link: it points into a different DNA and
resolves frontend-side, exactly as `proposal_id` resolves against the hREA cell today. The
reference is one-directional by design. Nobody can go from a listing to its conversations.

No status enum on `Message`. Deletion is leave-and-remove at the clone level, per the
design note, not soft-delete per entry.

## 6. Link types

    PathToMessage        anchor "messages.{bucket}" → Message      time-bucketed, Volla's
                                                                   pagination pattern
    MessageUpdates       original → updated                        edit chain
    PathToConfig         anchor "config" → ConversationConfig      single well-known entry

No `AgentToMessage`. Agent-centric discovery exists to scope a global DHT to one agent's
own data; inside a clone every message is already in scope for every participant, and the
author field carries attribution. Adding it would be a link per message for no query.

The inbox is not a link type here. The conversation list is assembled frontend-side by
enumerating installed clones, which is step four.

## 7. Validation

    genesis_self_check_2      local courtesy check on the joining agent's own device.
                              Verifies the proof parses and the signature verifies. Can be
                              skipped by a modified conductor, so it is a clean early error
                              and nothing more.

    validate()                the real gate. Match AgentValidationPkg, take membrane_proof,
                              decode, verify creator_signature against progenitor_pubkey
                              from properties, confirm conversation_id matches properties
                              and target_agent matches the joining agent. Reject otherwise.
                              Accept when progenitor_pubkey is None (dev mode).

    Message                   content non-empty, max length TBC, created_at non-zero.
    ConversationConfig        participants non-empty, created_at non-zero.

All of the above is deterministic: signature verification and property reads only, no DHT
reads at all. This is why the constraint recorded in R&O's `administration` integrity zome,
that `get_links` is unavailable in HDI 0.7.0 validation, does not apply. Authority travels
with the action as a signature rather than being looked up in a set.

## 8. Deliberately deferred

- Attachments and chunking. Clone-local and unencrypted, so `holochain-open-dev/file-storage`
  suits directly, but the current payload ceiling is unverified.
- Group conversations. MVP is one to one, which is what makes a single creator-progenitor
  sufficient.
- Clone limit. Set in `workdir/happ.yaml` at step four, after conductor cost at high cell
  count is measured.

## 9. Known hazard for step four

`init` runs lazily, on a cell's first zome call, and the messaging zome commits its cap
grant there. A freshly created or joined clone cell has therefore never run `init`, so an
inbound remote signal is dropped silently, with no error at either end. The clone lifecycle
must call `ping` on each new clone cell, on both the creating and joining side, before
relying on signalling. Recorded on issue #91.
