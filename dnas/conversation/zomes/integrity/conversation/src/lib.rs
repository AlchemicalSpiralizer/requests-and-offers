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
  pub progenitor: AgentPubKey,

  /// Opaque random identifier for this conversation.
  ///
  /// DELIBERATE DIVERGENCE FROM VOLLA. Volla checks a proof against
  /// `modifiers.network_seed`, so for them the conversation id *is* the seed.
  /// R&O cannot do that: a conversation identifier may be stored on a public
  /// hREA agreement (note section 5), and the seed must stay secret because
  /// kitsune2's space read route returns a space's agent list to any caller on
  /// an unauthenticated bootstrap (note section 6). Volla has no shared member
  /// directory to correlate an enumerated agent list against; R&O does, which is
  /// exactly what makes enumeration a social graph leak here and not there.
  pub conversation_id: String,
}

// ============================================================================
// MEMBRANE PROOF
// ============================================================================

/// Naming follows Volla's `MembraneProofData` / `MembraneProofEnvelope` pair.
///
/// Volla also carries an `as_role: u32`. Not adopted here: the design note does
/// not specify roles, and administrator invitation (note section 10) is not yet
/// designed. Adding a field we have not specified would be inventing.
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
  let info = dna_info()?;

  // Dev mode: no properties supplied at all. Encoded msgpack nil is one byte.
  if info.modifiers.properties.bytes().len() == 1 {
    return Ok(ValidateCallbackResult::Valid);
  }

  let props = Properties::try_from(info.modifiers.properties).map_err(|e| wasm_error!(e))?;

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
  Text,
  System,
}

/// Conversation metadata.
///
/// There is NO `participants` field. The note is explicit: participants are the
/// clone's membrane, not a field on an entry. Recording them again would
/// partially reintroduce the exposure isolation exists to remove.
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

  pub created_at: Timestamp,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Message {
  /// Plaintext. A clone contains exactly its participants, who hold the
  /// plaintext by definition (note section 6).
  pub content: String,

  /// Distinguishes member messages from system messages, of which the
  /// administrator-invitation notice is one.
  pub message_type: MessageType,

  pub reply_to: Option<ActionHash>,
  pub created_at: Timestamp,
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
  ConversationConfig(ConversationConfig),
  Message(Message),
}

// ============================================================================
// LINK TYPES
// ============================================================================

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

const MAX_MESSAGE_BYTES: usize = 10_000;

fn validate_message(message: &Message) -> ExternResult<ValidateCallbackResult> {
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

  if message.created_at == Timestamp::ZERO {
    return Ok(ValidateCallbackResult::Invalid(
      "message created_at must be non-zero".to_string(),
    ));
  }

  Ok(ValidateCallbackResult::Valid)
}

fn validate_conversation_config(
  config: &ConversationConfig,
) -> ExternResult<ValidateCallbackResult> {
  if config.created_at == Timestamp::ZERO {
    return Ok(ValidateCallbackResult::Invalid(
      "conversation config created_at must be non-zero".to_string(),
    ));
  }

  Ok(ValidateCallbackResult::Valid)
}

fn validate_entry(entry: &EntryTypes) -> ExternResult<ValidateCallbackResult> {
  match entry {
    EntryTypes::Message(message) => validate_message(message),
    EntryTypes::ConversationConfig(config) => validate_conversation_config(config),
  }
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
  match op.flattened::<EntryTypes, LinkTypes>()? {
    FlatOp::StoreEntry(store_entry) => match store_entry {
      OpEntry::CreateEntry { app_entry, .. } => validate_entry(&app_entry),
      OpEntry::UpdateEntry { app_entry, .. } => validate_entry(&app_entry),
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterUpdate(update_entry) => match update_entry {
      OpUpdate::Entry { app_entry, action } => {
        match validate_update_author(action.original_action_address, &action.author)? {
          ValidateCallbackResult::Valid => validate_entry(&app_entry),
          other => Ok(other),
        }
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterDelete(_) => reject_delete(),

    FlatOp::RegisterCreateLink { link_type, .. } => match link_type {
      LinkTypes::PathToMessage => Ok(ValidateCallbackResult::Valid),
      LinkTypes::MessageUpdates => Ok(ValidateCallbackResult::Valid),
      LinkTypes::PathToConfig => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterDeleteLink { link_type, .. } => match link_type {
      LinkTypes::PathToMessage => Ok(ValidateCallbackResult::Valid),
      LinkTypes::MessageUpdates => Ok(ValidateCallbackResult::Valid),
      LinkTypes::PathToConfig => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::StoreRecord(store_record) => match store_record {
      OpRecord::CreateEntry { app_entry, .. } => validate_entry(&app_entry),
      OpRecord::UpdateEntry { app_entry, .. } => validate_entry(&app_entry),
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
