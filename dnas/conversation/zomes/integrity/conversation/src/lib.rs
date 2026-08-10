use hdi::prelude::*;

/// Volla's production shape: a plain `AgentPubKey`, not the base64 string the shared
/// `requests_and_offers` DNA uses, because a clone receives its properties from the clone
/// creation call at runtime rather than from YAML.
#[derive(Serialize, Deserialize, Debug, SerializedBytes, Clone)]
pub struct Properties {
  /// Every participant in this conversation, ascending by key bytes.
  ///
  /// Properties feed the DNA hash, so an unordered pair would let two participants derive
  /// two different hashes from the same conversation and land in separate networks with no
  /// error anywhere. `check_agent` enforces the ordering rather than trusting it.
  ///
  /// Both hold the same authority: either may admit an administrator. This is what makes
  /// unilateral invitation possible for both participants rather than only the one who
  /// answered the listing.
  pub peers: Vec<AgentPubKey>,

  /// Opaque random identifier, deliberately NOT the network seed as it is in Volla. A
  /// conversation id may reach a public hREA agreement, and the seed must stay secret:
  /// kitsune2 0.4.1's `GET /bootstrap/{space}` returns a space's agent list to any caller
  /// when no authentication hook is configured (note section 6). The seed must also be
  /// random and transmitted, never derived from public values.
  pub conversation_id: String,

  /// The listing this conversation concerns, or `None` for a direct conversation. Points
  /// into the shared DNA and is resolved frontend-side, as hREA proposals already are.
  ///
  /// In properties rather than on an entry (note section 9): creation-time context that
  /// never changes, already travelling with the invitation, and readable with no DHT read.
  /// Properties being immutable also means a conversation cannot be re-pointed at another
  /// listing.
  pub context_hash: Option<ActionHash>,

  pub context_type: ContextType,

  /// The bucket the conversation opened in, giving a joining agent a floor to walk forward
  /// from. A fresh joiner, in particular an invited administrator reading the whole history
  /// (note section 10), holds no message to walk backward from and would otherwise have no
  /// way to find where the conversation starts. `validate_message` refuses any message below
  /// it, so declaring a late start cannot hide earlier messages: they become uncommittable
  /// rather than merely hard to find.
  pub start_bucket: u32,
}

/// False for the empty base cell, which carries no properties.
///
/// A base cell is provisioned on every install because `strategy: clone_only` hits
/// `unimplemented!()` in `holochain_conductor_api-0.6.1/src/app_interface.rs` at line 491,
/// byte-identical on upstream `main-0.6`. `deferred: true` is the same branch.
/// `dna_info()` is deterministic, so this is permitted in validation.
pub fn is_conversation_cell() -> ExternResult<bool> {
  Ok(dna_info()?.modifiers.properties.bytes().len() != 1)
}

/// Volla's naming. Their `as_role: u32` is not adopted: note section 10 gives an invited
/// administrator no distinct role.
#[derive(Serialize, Deserialize, Debug, SerializedBytes, Clone)]
pub struct MembraneProofData {
  pub conversation_id: String,
  pub for_agent: AgentPubKey,

  /// Inside the signed data, not on the envelope: the signature covers the claim of who
  /// issued it, so the signer field cannot be swapped for another peer's after signing.
  pub signer: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug, SerializedBytes)]
pub struct MembraneProofEnvelope {
  pub signature: Signature,
  pub data: MembraneProofData,
}

/// Deterministic: a properties read and a signature verification, no DHT access.
///
/// The signature covers the `MembraneProofData` struct rather than raw bytes, so `sign` and
/// `verify_signature` serialise through the same mechanism and cannot drift apart. No shared
/// byte-encoding helper is needed; do not add one.
pub fn check_agent(
  agent_pub_key: AgentPubKey,
  membrane_proof: Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
  // The base cell must be joinable or the app will not install. It is not writable.
  if !is_conversation_cell()? {
    return Ok(ValidateCallbackResult::Valid);
  }

  let props =
    Properties::try_from(dna_info()?.modifiers.properties).map_err(|e| wasm_error!(e))?;

  // `windows(2)` with strict `<` rejects an unordered pair and a duplicated key together.
  // Not `is_sorted`, whose stabilisation varies by toolchain.
  if props.peers.len() < 2 || !props.peers.windows(2).all(|w| w[0] < w[1]) {
    return Ok(ValidateCallbackResult::Invalid(
      "conversation properties must carry at least two peers, ascending and distinct".to_string(),
    ));
  }

  // A Direct conversation concerns no listing; every other kind concerns exactly one.
  // Properties feed the DNA hash, so this cannot be corrected later. Refuse at genesis
  // rather than admit a clone whose context is uninterpretable.
  if (props.context_type == ContextType::Direct) != props.context_hash.is_none() {
    return Ok(ValidateCallbackResult::Invalid(
      "a Direct conversation must carry no context hash, and any other kind must carry one"
        .to_string(),
    ));
  }

  // Participants are admitted by identity; nobody issues them a proof for their own clone.
  if props.peers.contains(&agent_pub_key) {
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

      if !props.peers.contains(&envelope.data.signer) {
        return Ok(ValidateCallbackResult::Invalid(
          "membrane proof was not signed by a participant in this conversation".to_string(),
        ));
      }

      if verify_signature(
        envelope.data.signer.clone(),
        envelope.signature,
        envelope.data,
      )? {
        return Ok(ValidateCallbackResult::Valid);
      }

      Ok(ValidateCallbackResult::Invalid(
        "membrane proof signature invalid".to_string(),
      ))
    }
  }
}

/// Request, Offer, Direct. The note's list; Organization is not in it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ContextType {
  Request,
  Offer,
  Direct,
}

/// Committed rather than rendered, because note section 10 requires the administrator
/// invitation announcement to be an entry a modified client cannot suppress. Structured
/// rather than prose so the member-facing wording stays a UI string, revisable and
/// translatable without a DNA change. `AdminInvited` names only the administrator; the
/// inviting participant is the action's author. Invitation policy is recorded on #91, and
/// the wording is a governance matter.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SystemEvent {
  AdminInvited { admin: AgentPubKey },

  /// The hREA proposal id, announced when a conversation reaches an agreement. This is not
  /// creation-time context and so cannot live in properties: a conversation produces its
  /// agreement mid-life (note section 5). Announced in the stream at the moment the deal was
  /// struck, and resolved frontend-side like `context_hash`.
  AgreementReached { proposal_id: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
  Text,
  System(SystemEvent),
}

/// No `created_at`. The action header carries a timestamp, and a client-supplied one would
/// be forgeable: a participant could date a message into the past and have every client
/// render it earlier in the thread than it was sent.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct Message {
  /// Plaintext (note section 6), and empty for system messages, whose payload is the event.
  pub content: String,

  pub message_type: MessageType,
  pub reply_to: Option<ActionHash>,

  /// The window this message belongs to, and the link base pagination walks.
  ///
  /// A field rather than a value derived at read time, because a link needs its base when
  /// the message is committed. This is not the `created_at` case: that field was redundant
  /// beside the action timestamp and bought nothing, whereas the bucket decides whether a
  /// message is found at all. `validate_message` checks it against the action's own
  /// timestamp, so a client cannot file a message into a window the other participant will
  /// not fetch. Volla carries the same field and validates nothing
  /// (`dnas/relay/zomes/integrity/relay/src/message.rs` line 22).
  pub bucket: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
  Message(Message),
}

#[derive(Serialize, Deserialize)]
#[hdk_link_types]
pub enum LinkTypes {
  /// Time-bucketed for pagination. Bucket width not yet chosen.
  PathToMessage,

  MessageUpdates,
}

/// Chosen for text rather than inherited from a crypto limit. The platform ceiling is
/// `ENTRY_SIZE_LIMIT`, 4,000,000 bytes (`holochain_integrity_types-0.6.1/src/entry.rs` line
/// 30, enforced at `app_entry_bytes.rs` line 50), and every transport above it is far
/// higher: 64 MB per app-websocket message, 100 MB per iroh frame by default. 64 KB is past
/// any real chat message while still bounding the storage-abuse surface, since anything
/// committed here is stored and gossiped by every participant. Attachments are chunked
/// entries and are not governed by this.
///
/// The previous 8192 came from lair's IPC ceiling, which bounds an encryption call, not an
/// entry. Content inside a clone is not encrypted (note section 6), and the hybrid route
/// wraps only a 32-byte key, so that ceiling never bound a message.
const MAX_MESSAGE_BYTES: usize = 65_536;

/// Thirty days in microseconds. Fixed windows rather than calendar months: integer
/// arithmetic only, no variable month length and no timezone, so the coordinator and this
/// validator cannot disagree about where a boundary falls. Wide enough that a sparse
/// conversation is a short walk back for a client fetching several buckets at a time.
/// Hotspotting is not a concern here because a clone holds one two-party conversation, not
/// every conversation in a network.
const BUCKET_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;

/// How long a message stays editable, measured from when it was first sent.
///
/// Deliberately a separate constant from `BUCKET_MICROS` even though both are thirty days
/// today. The bucket width is an indexing choice and this is a policy about correcting the
/// record; they coincide by accident, and tying one to the other would make changing either
/// silently change the other. Nothing about the edit rule refers to a bucket boundary, so a
/// message sent late in a window keeps its full window.
const EDIT_WINDOW_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;

/// The anchor a bucket's messages are linked from. Volla's shape
/// (`dnas/relay/zomes/integrity/relay/src/lib.rs` line 11), and in the integrity crate for
/// the same reason: the coordinator and `validate_message_link` must derive one base.
const MESSAGES_PATH_PREFIX: &str = "messages";

pub fn messages_path(bucket: u32) -> Path {
  Path::from(format!("{}.{}", MESSAGES_PATH_PREFIX, bucket))
}

/// One definition, used by both the coordinator and validation below, so the two cannot
/// drift. Volla places the equivalent helper in its integrity crate
/// (`dnas/relay/zomes/integrity/relay/src/lib.rs` line 11).
///
/// Negative timestamps clamp to bucket zero rather than wrapping through the `as u32` cast.
pub fn bucket_from_timestamp(timestamp: Timestamp) -> u32 {
  (timestamp.as_micros().max(0) / BUCKET_MICROS) as u32
}

/// A message is either being created or edited, and the two are bucketed against different
/// timestamps: a create against its own, an edit against the message's first one, so that
/// editing never moves a message in the thread.
enum MessageTiming {
  Created(Timestamp),
  Updated { original: Timestamp, updated: Timestamp },
}

/// Walk an update chain back to the create that started it.
///
/// Each `Update` names the action it replaced, so following `original_action_address` reaches
/// the create in as many steps as there are revisions, each one a deterministic
/// `must_get_action`. Walking to the root rather than stopping at the previous revision is the
/// point: a window measured from the previous revision would let a chain of edits carry
/// editability forward indefinitely, thirty days at a time.
fn root_create_timestamp(action_hash: ActionHash) -> ExternResult<Option<Timestamp>> {
  let mut hash = action_hash;

  loop {
    let action = must_get_action(hash)?;

    match action.action() {
      Action::Create(create) => return Ok(Some(create.timestamp)),
      Action::Update(update) => hash = update.original_action_address.clone(),
      _ => return Ok(None),
    }
  }
}

fn validate_message(
  message: &Message,
  timing: MessageTiming,
  start_bucket: u32,
) -> ExternResult<ValidateCallbackResult> {
  // Timestamps are fixed in their actions, so author and validator read the same values and
  // exact equality is correct. There is no second clock to tolerate.
  let bucketed_against = match timing {
    MessageTiming::Created(created) => created,
    MessageTiming::Updated { original, updated } => {
      let elapsed = updated.as_micros() - original.as_micros();

      // A negative elapsed time means the edit claims to precede the message it edits, which
      // is never legitimate.
      if !(0..=EDIT_WINDOW_MICROS).contains(&elapsed) {
        return Ok(ValidateCallbackResult::Invalid(format!(
          "a message may be edited for {} days after it was sent",
          EDIT_WINDOW_MICROS / (24 * 60 * 60 * 1_000_000)
        )));
      }

      original
    }
  };

  let expected = bucket_from_timestamp(bucketed_against);
  if message.bucket != expected {
    return Ok(ValidateCallbackResult::Invalid(format!(
      "message bucket {} does not match the bucket its timestamp falls in, {}",
      message.bucket, expected
    )));
  }

  if message.bucket < start_bucket {
    return Ok(ValidateCallbackResult::Invalid(format!(
      "message bucket {} precedes the conversation start bucket {}",
      message.bucket, start_bucket
    )));
  }

  match &message.message_type {
    // The event is the payload.
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

      // `String::len` is bytes, not chars, which is what the ceiling is measured in.
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

/// `start_bucket` comes from properties, which are deterministic, so reading them here is
/// permitted in validation.
fn validate_entry(
  entry: &EntryTypes,
  timing: MessageTiming,
) -> ExternResult<ValidateCallbackResult> {
  let props =
    Properties::try_from(dna_info()?.modifiers.properties).map_err(|e| wasm_error!(e))?;

  match entry {
    EntryTypes::Message(message) => validate_message(message, timing, props.start_bucket),
  }
}

/// Shared by the three op arms that see an update, so the root walk and its failure case are
/// written once.
fn validate_updated_entry(
  entry: &EntryTypes,
  original_action_address: ActionHash,
  updated: Timestamp,
) -> ExternResult<ValidateCallbackResult> {
  match root_create_timestamp(original_action_address)? {
    Some(original) => validate_entry(entry, MessageTiming::Updated { original, updated }),
    None => Ok(ValidateCallbackResult::Invalid(
      "an update must replace a create or another update".to_string(),
    )),
  }
}

/// The base cell may be joined but never written to.
///
/// Its membrane admits anyone and every install shares its DNA hash, so it is one open
/// network every member joins. Nothing sensitive can leak from it, but left writable it is a
/// storage-abuse surface, since anything committed there is stored and gossiped by every
/// member's node. Integrity-level because a coordinator guard stops nobody who compiles
/// their own coordinator against this crate.
fn refuse_base_cell_write() -> ExternResult<ValidateCallbackResult> {
  Ok(ValidateCallbackResult::Invalid(
    "the base conversation cell holds no conversation and accepts no writes".to_string(),
  ))
}

/// NOT IN THE DESIGN NOTE. Without it either participant could rewrite the other's messages
/// through the update chain, and the plain read every client performs would show the altered
/// text under the original author's name. `must_get_action` on a hash the action already
/// names is deterministic, so it is permitted here; enumerating with `get_links` would not be.
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

/// NOT IN THE DESIGN NOTE. A message's link base is fully derivable from its own validated
/// bucket, so a base that disagrees carries no information and can only mislead. Left
/// unchecked, a participant could commit correctly bucketed messages and file the links under
/// a bucket nobody walks: an administrator invited to read the whole history (note section 10)
/// would then find the other participant's messages and not theirs. That is selective
/// suppression in exactly the case the invitation exists for.
///
/// `must_get_valid_record` on a hash the link already names is deterministic, so it is
/// permitted here.
fn validate_message_link(
  base_address: AnyLinkableHash,
  target_address: AnyLinkableHash,
) -> ExternResult<ValidateCallbackResult> {
  let Some(target_action_hash) = target_address.into_action_hash() else {
    return Ok(ValidateCallbackResult::Invalid(
      "a PathToMessage link must target an action hash".to_string(),
    ));
  };

  let record = must_get_valid_record(target_action_hash)?;

  let Some(entry) = record.entry().as_option() else {
    return Ok(ValidateCallbackResult::Invalid(
      "a PathToMessage link must target a message entry".to_string(),
    ));
  };

  // `hdk_entry_helper` already yields a `WasmError` here, unlike the `SerializedBytes`
  // conversions elsewhere in this file, so it needs no wrapping.
  let message = Message::try_from(entry)?;
  let expected: AnyLinkableHash = messages_path(message.bucket).path_entry_hash()?.into();

  if base_address != expected {
    return Ok(ValidateCallbackResult::Invalid(format!(
      "a message in bucket {} must be linked from that bucket's path",
      message.bucket
    )));
  }

  Ok(ValidateCallbackResult::Valid)
}

/// NOT IN THE DESIGN NOTE. Holochain does not require the author of a delete-link action to
/// be the author of the link it deletes. Without this check either participant could remove
/// the other's message links, emptying the thread's index for everyone who reads it,
/// including an invited administrator. Suppressing the other party's messages rather than
/// merely hiding one's own, so this matters more than the misfiling above.
fn validate_delete_link_author(
  original_action: &CreateLink,
  deleting_author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
  match &original_action.author == deleting_author {
    true => Ok(ValidateCallbackResult::Valid),
    false => Ok(ValidateCallbackResult::Invalid(
      "only the agent who created a link may delete it".to_string(),
    )),
  }
}

/// NOT IN THE DESIGN NOTE. The same forgery one layer down: linking an entry you authored
/// yourself from the other participant's message as its update.
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

/// Note section 8: crypto-shredding is unavailable on this stack, so removal is
/// leave-and-remove, which uninstalls the clone and its local databases. A delete would only
/// write a tombstone beside an entry that remains in the DHT regardless. Archiving is clone
/// disable. Volla does permit deletes, so this is a conscious divergence.
fn reject_delete() -> ExternResult<ValidateCallbackResult> {
  Ok(ValidateCallbackResult::Invalid(
    "entries are not deletable in a conversation; removal is leaving the conversation".to_string(),
  ))
}

/// Runs on the joining agent's own device: a courtesy check a modified conductor can skip,
/// not the gate. The macro maps this to the versioned extern `genesis_self_check_2`.
#[hdk_extern]
pub fn genesis_self_check(data: GenesisSelfCheckData) -> ExternResult<ValidateCallbackResult> {
  check_agent(data.agent_key, data.membrane_proof)
}

/// Runs on every agent already in the clone. This is the real gate.
pub fn validate_agent_joining(
  agent_pub_key: AgentPubKey,
  membrane_proof: &Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
  check_agent(agent_pub_key, (*membrane_proof).clone())
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
  // Read once. Only the app-entry and link arms consult it, because the base cell must stay
  // joinable.
  let in_conversation = is_conversation_cell()?;

  match op.flattened::<EntryTypes, LinkTypes>()? {
    // Create and Update carry different action types, so the arms cannot be combined once
    // the timestamp is needed.
    FlatOp::StoreEntry(store_entry) => match store_entry {
      OpEntry::CreateEntry { app_entry, action } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_entry(&app_entry, MessageTiming::Created(action.timestamp))
      }
      OpEntry::UpdateEntry {
        app_entry, action, ..
      } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_updated_entry(&app_entry, action.original_action_address, action.timestamp)
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterUpdate(update_entry) => match update_entry {
      OpUpdate::Entry { app_entry, action } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        let timestamp = action.timestamp;
        let original_action_address = action.original_action_address.clone();
        match validate_update_author(action.original_action_address, &action.author)? {
          ValidateCallbackResult::Valid => {
            validate_updated_entry(&app_entry, original_action_address, timestamp)
          }
          other => Ok(other),
        }
      }
      _ => Ok(ValidateCallbackResult::Valid),
    },

    FlatOp::RegisterDelete(_) => reject_delete(),

    FlatOp::RegisterCreateLink {
      link_type,
      base_address,
      target_address,
      action,
      ..
    } => {
      if !in_conversation {
        return refuse_base_cell_write();
      }
      match link_type {
        LinkTypes::PathToMessage => validate_message_link(base_address, target_address),
        LinkTypes::MessageUpdates => validate_update_link_author(base_address, &action.author),
      }
    }

    FlatOp::RegisterDeleteLink {
      original_action,
      action,
      ..
    } => {
      if !in_conversation {
        return refuse_base_cell_write();
      }
      validate_delete_link_author(&original_action, &action.author)
    }

    FlatOp::StoreRecord(store_record) => match store_record {
      OpRecord::CreateEntry { app_entry, action } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_entry(&app_entry, MessageTiming::Created(action.timestamp))
      }
      OpRecord::UpdateEntry {
        app_entry, action, ..
      } => {
        if !in_conversation {
          return refuse_base_cell_write();
        }
        validate_updated_entry(&app_entry, action.original_action_address, action.timestamp)
      }
      OpRecord::DeleteEntry { .. } => reject_delete(),
      _ => Ok(ValidateCallbackResult::Valid),
    },

    // The membrane: a CreateAgent action is preceded by an AgentValidationPkg carrying the
    // joining agent's proof.
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
