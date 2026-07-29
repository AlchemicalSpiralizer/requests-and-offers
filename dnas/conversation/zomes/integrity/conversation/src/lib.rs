use hdi::prelude::*;

// ============================================================================
// DNA PROPERTIES
// ============================================================================

/// Properties supplied per clone at creation time.
///
/// Shape follows Volla Messages' production relay DNA, which runs this same
/// clone-per-conversation model: the progenitor is a plain `AgentPubKey`, not a
/// base64 string. The shared `requests_and_offers` DNA uses `Option<String>`
/// because its properties come from `workdir/happ.yaml` and YAML carries only
/// text; a clone receives its properties from the clone creation call at
/// runtime, where the client already holds an agent key as raw bytes.
#[derive(Serialize, Deserialize, Debug, SerializedBytes, Clone)]
pub struct Properties {
  /// The conversation's creator. Issues every membrane proof for this clone.
  ///
  /// KNOWN CONFLICT, and a required fix rather than a tidy-up. Administrator
  /// invitation is unilateral: either participant may invite, and the other is
  /// told (see `SystemEvent`). Only the progenitor can sign a proof here, and the
  /// progenitor is whichever member responded to the listing, so exactly one of
  /// the two can invite and which one is an accident of who answered first.
  ///
  /// Resolving it means both peers' keys living in these properties and the
  /// envelope naming its signer, with `check_agent` verifying the signature and
  /// then checking the signer is one of the two. Properties are not an entry, so
  /// note section 9's refusal of a participants field is untouched, and they are
  /// unreadable without the DNA. Both peers must already supply identical
  /// properties for their DNA hashes to converge, and the responder knows both
  /// keys, so nothing new has to travel.
  ///
  /// Deliberately not done in this change: it rewrites `issue_membrane_proof` and
  /// wants its own test against a membrane gate that has never been exercised.
  pub progenitor: AgentPubKey,

  /// Opaque random identifier for this conversation.
  ///
  /// DELIBERATE DIVERGENCE FROM VOLLA. Volla checks a proof against
  /// `modifiers.network_seed`, so for them the conversation id *is* the seed.
  /// R&O cannot do that. A conversation identifier may be stored on a public hREA
  /// agreement (note section 5), and the seed must stay secret, because
  /// kitsune2 0.4.1's space read route (`GET /bootstrap/{space}`) returns the
  /// agent list for whatever space identifier the caller supplies, and with no
  /// authentication hook configured the server issues bearer tokens freely and
  /// treats every request as successful (note section 6). Volla has no shared
  /// member directory to correlate an enumerated agent list against; R&O does,
  /// which is what makes enumeration a social graph leak here and not there.
  ///
  /// The complementary constraint belongs with whoever writes clone creation,
  /// which does not exist yet (note section 12, step 4): the network seed must be
  /// random and transmitted, never derived from public values. A seed derived
  /// from a listing hash and an agent key would be computable by every member,
  /// handing over the conversation graph to anyone willing to enumerate. The
  /// membrane would still keep them out of the clone, but membership enumeration
  /// alone is the leak this design exists to prevent.
  pub conversation_id: String,
}

/// Does this cell hold a conversation, or is it the empty base cell?
///
/// One definition rather than a byte test repeated at each site.
///
/// A base conversation cell is provisioned on every install, because
/// `strategy: clone_only` hits `unimplemented!()` in
/// `holochain_conductor_api-0.6.1/src/app_interface.rs` at line 491 while
/// building `AppInfo`, which the frontend calls constantly. That code is
/// byte-identical on upstream `main-0.6`, so this affects the whole 0.6 line
/// rather than our pin and is not a workaround waiting to be deleted.
///
/// `workdir/happ.yaml` gives the conversation role `properties: ~`, which
/// encodes as msgpack nil, one byte. A clone receives real properties from the
/// clone creation call.
///
/// `dna_info()` is deterministic and therefore permitted in validation.
pub fn is_conversation_cell() -> ExternResult<bool> {
  Ok(dna_info()?.modifiers.properties.bytes().len() != 1)
}

// ============================================================================
// MEMBRANE PROOF
// ============================================================================

/// Naming follows Volla's `MembraneProofData` / `MembraneProofEnvelope` pair.
///
/// Volla also carries an `as_role: u32`. Not adopted here, but not for want of a
/// design: note section 10 specifies administrator invitation in full and gives
/// an invited administrator no distinct role. They are an ordinary agent inside
/// the clone, admitted by the same kind of proof as a participant, and what
/// marks the event is the committed `SystemEvent::AdminInvited` rather than
/// anything carried in the proof. A role field would have nothing to say.
#[derive(Serialize, Deserialize, Debug, SerializedBytes, Clone)]
pub struct MembraneProofData {
  pub conversation_id: String,
  pub for_agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug, SerializedBytes)]
pub struct MembraneProofEnvelope {
  pub signature: Signature,
  pub data: MembraneProofData,
}

/// Decode a membrane proof and check it against this clone's properties.
///
/// Deterministic: a properties read and a signature verification, no DHT access.
///
/// The signature is taken over the `MembraneProofData` struct, not over raw
/// bytes. The issuing coordinator calls `sign(progenitor, data)` and this calls
/// `verify_signature(progenitor, signature, data)`; both serialise through the
/// same mechanism, so the two sides cannot drift apart. This is Volla's approach
/// and it needs no shared byte-encoding helper.
pub fn check_agent(
  agent_pub_key: AgentPubKey,
  membrane_proof: Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
  // The base cell has no membrane. It must be joinable or the app will not
  // install at all. It is not writable: see `refuse_base_cell_write`.
  if !is_conversation_cell()? {
    return Ok(ValidateCallbackResult::Valid);
  }

  let props =
    Properties::try_from(dna_info()?.modifiers.properties).map_err(|e| wasm_error!(e))?;

  // The creator is progenitor of their own clone and issues everyone else's
  // proof, so nobody has issued one to them.
  if agent_pub_key == props.progenitor {
    return Ok(ValidateCallbackResult::Valid);
  }

  match membrane_proof {
    None => Ok(ValidateCallbackResult::Invalid(
      "a membrane proof is required to join this conversation".to_string(),
    )),
    Some(serialized_proof) => {
      let envelope =
        MembraneProofEnvelope::try_from((*serialized_proof).clone()).map_err(|e| wasm_error!(e))?;

      if envelope.data.conversation_id != props.conversation_id {
        return Ok(ValidateCallbackResult::Invalid(
          "membrane proof is not for this conversation".to_string(),
        ));
      }

      if envelope.data.for_agent != agent_pub_key {
        return Ok(ValidateCallbackResult::Invalid(
          "membrane proof is not for this agent".to_string(),
        ));
      }

      if verify_signature(props.progenitor, envelope.signature, envelope.data)? {
        return Ok(ValidateCallbackResult::Valid);
      }

      Ok(ValidateCallbackResult::Invalid(
        "membrane proof signature invalid".to_string(),
      ))
    }
  }
}

// ============================================================================
// ENTRY TYPES  (note section 9)
// ============================================================================

/// Request, Offer, Direct. Exactly the note's list; Organization is not in it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ContextType {
  Request,
  Offer,
  Direct,
}

/// A structured system event, committed rather than rendered.
///
/// Note section 10 requires the administrator-invitation announcement to be a
/// committed entry rather than a client-side rendering, so a modified client
/// cannot suppress it. It does not require the announcement's prose to be
/// committed, and committing prose would buy nothing against that threat: a
/// client willing to hide a committed event is equally willing to blank a
/// committed string.
///
/// Keeping the event structured means the member-facing wording stays a UI
/// string, so it can be revised or translated without every historical entry
/// carrying the old text, and without a DNA change. The wording is a governance
/// matter (note sections 10 and 11) and is not settled here.
///
/// WHAT IS SETTLED, superseding note section 10's open question. Invitation is
/// unilateral with notice: either participant may invite an administrator and the
/// other is told. Section 10 leaves "whether both participants must agree" open
/// for governance, and mutual agreement fails on its own logic. The case the
/// mechanism exists for is a participant behaving badly, and they will not agree
/// to being observed, so a consent requirement disables the instrument precisely
/// when it is needed. Notice costs the inviter nothing they can be harmed by:
/// there are no deletes in this design and leaving removes only your own copy, so
/// the history an administrator arrives to read is intact whatever the other
/// party does on being told.
///
/// `AdminInvited` names only the administrator. The inviting participant is the
/// action's author and does not need recording twice.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SystemEvent {
  AdminInvited { admin: AgentPubKey },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
  Text,
  System(SystemEvent),
}

/// Conversation metadata.
///
/// There is NO `participants` field. The note is explicit: participants are the
/// clone's membrane, not a field on an entry. Recording them again would
/// partially reintroduce the exposure isolation exists to remove.
///
/// There is also no `created_at`. Every action header already carries a
/// timestamp, reachable as `record.action().timestamp()`. A consequence worth
/// knowing: with no time field, this entry is addressed purely by its content,
/// so committing the same configuration twice yields one entry rather than two.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct ConversationConfig {
  /// The listing this conversation concerns. A stored identifier, not a DHT
  /// link: it points into the shared DNA and resolves frontend-side, as hREA
  /// proposals already do over GraphQL.
  pub context_hash: Option<ActionHash>,

  pub context_type: ContextType,

  /// Optional hREA proposal id, also resolved frontend-side.
  pub proposal_id: Option<String>,
}

/// A message.
///
/// No `created_at`. The action header carries a timestamp already, and a
/// client-supplied one would be both redundant and forgeable: a participant
/// could date a message into the past and have every client render it earlier in
/// the thread than it was sent. `record.action().timestamp()` is the committing
/// conductor's claim rather than the sender's free choice, and time bucketing
/// reads `sys_time()` on create and the action timestamp on update, so nothing
/// needs the field.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct Message {
  /// Plaintext, and empty for system messages, whose payload is the event.
  ///
  /// Note section 6 decides against encryption inside a clone: a clone contains
  /// exactly its participants, who hold the plaintext by definition, so
  /// encrypting content that only its intended readers can fetch buys key
  /// management and a device-loss failure mode for very little. Volla, a
  /// dedicated privacy messenger, reaches the same conclusion. Clone contents
  /// therefore sit unencrypted in the conductor's local databases, and
  /// device-level protection is the member's own disk encryption, which note
  /// section 11 tells members plainly.
  pub content: String,

  /// Distinguishes member messages from system messages, of which the
  /// administrator-invitation notice is one.
  pub message_type: MessageType,

  pub reply_to: Option<ActionHash>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
  ConversationConfig(ConversationConfig),
  Message(Message),
}

// ============================================================================
// LINK TYPES
// ============================================================================

#[derive(Serialize, Deserialize)]
#[hdk_link_types]
pub enum LinkTypes {
  /// Conversation to messages, time-bucketed for pagination. Bucket width is
  /// not yet chosen and is set once message volumes are known.
  PathToMessage,

  /// The message update chain.
  MessageUpdates,

  /// NOT IN THE DESIGN NOTE. The note lists the two link types above and does
  /// not say how the configuration entry is discovered. A DHT entry with nothing
  /// linking to it is unreachable, so an anchor is functionally required. Raised
  /// as a gap to reconcile against the note rather than assumed settled.
  PathToConfig,
}

// ============================================================================
// ENTRY VALIDATION
// ============================================================================

/// A product decision, pinned to one platform fact rather than a round number.
///
/// Nothing in the design note specifies a message size, and content here is
/// plaintext, so no crypto ceiling constrains it today. But note section 6
/// records that every zome crypto primitive routes through lair over IPC and
/// rejects a single call above 8192 bytes, and it deliberately keeps two
/// encryption routes open should they ever be wanted. A cap above that ceiling
/// would quietly foreclose encrypting a maximally-sized message without
/// chunking, which section 6 records as untested. Sitting at the ceiling costs
/// nothing: 8192 bytes is roughly 1,300 words, which is long for a chat message.
const MAX_MESSAGE_BYTES: usize = 8192;

fn validate_message(message: &Message) -> ExternResult<ValidateCallbackResult> {
  match &message.message_type {
    // The event is the payload. Committed prose would be untranslatable and
    // unrevisable, and buys nothing (see `SystemEvent`).
    MessageType::System(_) => {
      if !message.content.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
          "a system message must carry no content; its event is the payload".to_string(),
        ));
      }
    }

    MessageType::Text => {
      if message.content.trim().is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
          "message content must not be empty".to_string(),
        ));
      }

      if message.content.len() > MAX_MESSAGE_BYTES {
        return Ok(ValidateCallbackResult::Invalid(format!(
          "message content exceeds {} bytes",
          MAX_MESSAGE_BYTES
        )));
      }
    }
  }

  Ok(ValidateCallbackResult::Valid)
}

/// Nothing to check yet, deliberately.
///
/// `context_type` is an enum and therefore type-checked by deserialisation.
/// `context_hash` and `proposal_id` point into other cells and resolve
/// frontend-side, so this DNA cannot verify either without a DHT read, which
/// validation forbids. Kept as the named place for checks that do become
/// possible rather than inlined into `validate_entry`.
fn validate_conversation_config(
  _config: &ConversationConfig,
) -> ExternResult<ValidateCallbackResult> {
  Ok(ValidateCallbackResult::Valid)
}

fn validate_entry(entry: &EntryTypes) -> ExternResult<ValidateCallbackResult> {
  match entry {
    EntryTypes::Message(message) => validate_message(message),
    EntryTypes::ConversationConfig(config) => validate_conversation_config(config),
  }
}

/// The base cell may be joined but never written to.
///
/// NOT IN THE DESIGN NOTE, and not a design choice so much as a consequence of
/// one. Because a base cell is unavoidable (see `is_conversation_cell`) and its
/// membrane admits anyone, and because every install derives it from the same
/// `workdir/happ.yaml` and so shares its DNA hash, it is one open network that
/// every R&O user joins. No conversation ever lives there and nothing sensitive
/// can leak from it, but left writable it is a storage-abuse surface: entries
/// pushed into it would be stored and gossiped by every user's node.
///
/// This has to sit in the integrity zome rather than the coordinator. A
/// coordinator guard stops anyone calling our functions and stops nobody who
/// compiles their own coordinator against this crate.
fn refuse_base_cell_write() -> ExternResult<ValidateCallbackResult> {
  Ok(ValidateCallbackResult::Invalid(
    "the base conversation cell holds no conversation and accepts no writes".to_string(),
  ))
}

/// NOT IN THE DESIGN NOTE, flagged for review.
///
/// Without this, either participant could rewrite the other's messages through
/// the update chain. The forgery would be attributable via `get_details`, but
/// the plain read that every client performs would show the altered text under
/// the original author's name.
///
/// `must_get_action` on a hash the action already names is deterministic, so it
/// is permitted in validation. That is the distinction that matters: pinning one
/// record is fine, enumerating an open set with `get_links` is not.
fn validate_update_author(
  original_action_hash: ActionHash,
  updating_author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
  let original = must_get_action(original_action_hash)?;

  if original.action().author() != updating_author {
    return Ok(ValidateCallbackResult::Invalid(
      "only the agent who authored an entry may update it".to_string(),
    ));
  }

  Ok(ValidateCallbackResult::Valid)
}

/// NOT IN THE DESIGN NOTE, flagged alongside `validate_update_author`.
///
/// The entry-level author check stops one participant authoring an update to
/// another's message. Without this, they could instead link an entry they
/// authored themselves from the other's message as its update, and a client
/// walking the chain would render their text as the other's current message.
/// The same forgery, one layer down.
fn validate_update_link_author(
  base_address: AnyLinkableHash,
  linking_author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
  let Some(base_action_hash) = base_address.into_action_hash() else {
    return Ok(ValidateCallbackResult::Invalid(
      "a MessageUpdates link must be based on an action hash".to_string(),
    ));
  };

  let base = must_get_action(base_action_hash)?;

  match base.action().author() == linking_author {
    true => Ok(ValidateCallbackResult::Valid),
    false => Ok(ValidateCallbackResult::Invalid(
      "only the agent who authored a message may link an update to it".to_string(),
    )),
  }
}

/// Deletion is not an entry-level operation in this design.
///
/// Note section 8: crypto-shredding is unavailable on this stack, so the
/// primitive is leave-and-remove, which uninstalls the clone and removes its
/// local databases. That is real removal of local data rather than a
/// soft-delete flag on an entry which remains in the DHT regardless. Archiving
/// is clone disable.
///
/// Volla does permit entry deletes with validation. This is therefore a
/// conscious divergence, not an oversight.
fn reject_delete() -> ExternResult<ValidateCallbackResult> {
  Ok(ValidateCallbackResult::Invalid(
    "entries are not deletable in a conversation; removal is leaving the conversation".to_string(),
  ))
}

// ============================================================================
// MEMBRANE CALLBACKS
// ============================================================================

/// Runs on the joining agent's own device, before they have joined anything.
/// A courtesy check, not the gate: a modified conductor can skip it. Written as
/// `genesis_self_check`, which the macro maps to the versioned extern
/// `genesis_self_check_2`.
#[hdk_extern]
pub fn genesis_self_check(data: GenesisSelfCheckData) -> ExternResult<ValidateCallbackResult> {
  check_agent(data.agent_key, data.membrane_proof)
}

/// Runs on every agent already in the clone when a new agent tries to join.
/// This is the real gate.
pub fn validate_agent_joining(
  agent_pub_key: AgentPubKey,
  membrane_proof: &Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
  check_agent(agent_pub_key, (*membrane_proof).clone())
}

// ============================================================================
// UNIFIED VALIDATION CALLBACK
// ============================================================================

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
  // Read once. Every app-entry and link arm below consults it; agent activity
  // and chain-management records deliberately do not, because the base cell
  // must remain joinable.
  let in_conversation = is_conversation_cell()?;

  match op.flattened::<EntryTypes, LinkTypes>()? {
    FlatOp::StoreEntry(store_entry) => match store_entry {
      OpEntry::CreateEntry { app_entry, .. } | OpEntry::UpdateEntry { app_entry, .. } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_entry(&app_entry)
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterUpdate(update_entry) => match update_entry {
      OpUpdate::Entry { app_entry, action } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        match validate_update_author(action.original_action_address, &action.author)? {
          ValidateCallbackResult::Valid => validate_entry(&app_entry),
          other => Ok(other),
        }
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterDelete(_) => reject_delete(),

    FlatOp::RegisterCreateLink {
      link_type,
      base_address,
      action,
      ..
    } => {
      if !in_conversation {
        return refuse_base_cell_write();
      }
      match link_type {
        LinkTypes::PathToMessage => Ok(ValidateCallbackResult::Valid),
        LinkTypes::PathToConfig => Ok(ValidateCallbackResult::Valid),
        LinkTypes::MessageUpdates => validate_update_link_author(base_address, &action.author),
      }
    }

    FlatOp::RegisterDeleteLink { link_type, .. } => match link_type {
      LinkTypes::PathToMessage => Ok(ValidateCallbackResult::Valid),
      LinkTypes::MessageUpdates => Ok(ValidateCallbackResult::Valid),
      LinkTypes::PathToConfig => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::StoreRecord(store_record) => match store_record {
      OpRecord::CreateEntry { app_entry, .. } | OpRecord::UpdateEntry { app_entry, .. } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_entry(&app_entry)
      }
      OpRecord::DeleteEntry { .. } => reject_delete(),
      _ => Ok(ValidateCallbackResult::Valid),
    },

    // The membrane. A joining agent's CreateAgent action is preceded by an
    // AgentValidationPkg carrying their proof; this is where it is checked.
    FlatOp::RegisterAgentActivity(agent_activity) => match agent_activity {
      OpActivity::CreateAgent { agent, action } => {
        let previous_action = must_get_action(action.prev_action)?;
        match previous_action.action() {
          Action::AgentValidationPkg(AgentValidationPkg { membrane_proof, .. }) => {
            validate_agent_joining(agent, membrane_proof)
          }
          _ => Ok(ValidateCallbackResult::Invalid(
            "the previous action for a CreateAgent action must be an AgentValidationPkg"
              .to_string(),
          )),
        }
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },
  }
}
