use conversation_integrity::*;
use hdk::prelude::*;
use utils::errors::CommonError;

use crate::conversation_properties;
use crate::errors::ConversationError;

// ============================================================================
// WRITING
// ============================================================================

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateMessageInput {
  pub content: String,
  pub reply_to: Option<ActionHash>,
}

/// Commit a member message and index it under its bucket.
///
/// The bucket is derived here rather than accepted from the caller. Volla takes a whole
/// `Message` from its client, bucket included
/// (`dnas/relay/zomes/coordinator/relay/src/message.rs` line 15), which leaves one
/// client-supplied number deciding both the entry field and the link base with nothing
/// checking either. Deriving it means `validate_message` is checking a value this zome
/// computed, so the only way to file a message wrongly is to run a different coordinator,
/// which the integrity zome then refuses.
#[hdk_extern]
pub fn create_message(input: CreateMessageInput) -> ExternResult<Record> {
  commit_message(input.content, MessageType::Text, input.reply_to)
}

/// Shared by `create_message` and the system-message callers (`invite_admin`,
/// `announce_agreement`), so every message reaches the DHT and the index one way.
pub fn commit_message(
  content: String,
  message_type: MessageType,
  reply_to: Option<ActionHash>,
) -> ExternResult<Record> {
  // Refuses in the base cell, and hands back the properties the bucket floor lives in.
  conversation_properties()?;

  let bucket = bucket_from_timestamp(sys_time()?);

  let message = Message {
    content,
    message_type,
    reply_to,
    bucket,
  };

  let action_hash = create_entry(EntryTypes::Message(message))?;

  create_link(
    messages_path(bucket).path_entry_hash()?,
    action_hash.clone(),
    LinkTypes::PathToMessage,
    (),
  )?;

  get(action_hash, GetOptions::local())?
    .ok_or(CommonError::RecordNotFound("the message just committed".to_string()).into())
}

/// Announce an agreement in the conversation stream.
///
/// The proposal id is not creation-time context and so cannot live in the clone's properties:
/// a conversation produces its agreement mid-life (note section 5). Committed as a system
/// message at the moment the deal was struck, and resolved frontend-side.
#[hdk_extern]
pub fn announce_agreement(proposal_id: String) -> ExternResult<Record> {
  commit_message(
    String::new(),
    MessageType::System(SystemEvent::AgreementReached { proposal_id }),
    None,
  )
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateMessageInput {
  pub original_action_hash: ActionHash,
  pub previous_action_hash: ActionHash,
  pub content: String,
}

/// Edit a message's content. The integrity zome refuses an update authored by anyone but the
/// original author, and refuses a `MessageUpdates` link based on another agent's message.
///
/// The bucket is carried forward from the original rather than recomputed, so an edit does not
/// move a message in the thread, and `validate_message` buckets an update against the original
/// message's timestamp for the same reason.
///
/// The window check here is a courtesy that turns a validation rejection into a readable error
/// before anything is committed. Validation remains the gate, as it does for the base cell.
#[hdk_extern]
pub fn update_message(input: UpdateMessageInput) -> ExternResult<Record> {
  conversation_properties()?;

  let original = get(input.original_action_hash.clone(), GetOptions::default())?
    .ok_or(CommonError::RecordNotFound("the message being updated".to_string()))?;

  let entry = original
    .entry()
    .as_option()
    .ok_or(CommonError::EntryNotFound("the message being updated".to_string()))?;

  let previous = Message::try_from(entry)?;

  // The original create's own timestamp, which is what the window is measured from. Measuring
  // from the latest revision would let a chain of edits extend editability indefinitely.
  if !within_edit_window(original.action().timestamp(), sys_time()?) {
    return Err(ConversationError::EditWindowClosed.into());
  }

  let updated = Message {
    content: input.content,
    message_type: previous.message_type,
    reply_to: previous.reply_to,
    bucket: previous.bucket,
  };

  let action_hash = update_entry(input.previous_action_hash.clone(), updated)?;

  create_link(
    input.original_action_hash,
    action_hash.clone(),
    LinkTypes::MessageUpdates,
    (),
  )?;

  get(action_hash, GetOptions::local())?
    .ok_or(CommonError::RecordNotFound("the updated message".to_string()).into())
}

// ============================================================================
// READING
// ============================================================================

/// The original message followed by every revision of it, oldest first.
///
/// Nothing marks an edit inside the entry: a revision is an `Update` action, so a reader can
/// tell an edited message from an original by its action type and by the length of this chain.
/// A field would duplicate action data and be forgeable.
///
/// Every revision stays fetchable at its own action hash, and `reject_delete` in the integrity
/// zome means none of them can be tombstoned, so the edit history of a conversation cannot be
/// rewritten after the fact. No author filter is needed here: validation already refuses a
/// revision authored by anyone but the original author, and refuses a `MessageUpdates` link
/// based on another agent's message.
#[hdk_extern]
pub fn get_message_revisions(original_action_hash: ActionHash) -> ExternResult<Vec<Record>> {
  conversation_properties()?;

  let link_type_filter = LinkTypes::MessageUpdates
    .try_into_filter()
    .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.to_string())))?;

  let links = get_links(
    LinkQuery::new(original_action_hash.clone(), link_type_filter),
    GetStrategy::Network,
  )?;

  let mut records = Vec::with_capacity(links.len() + 1);

  if let Some(original) = get(original_action_hash, GetOptions::default())? {
    records.push(original);
  }

  for link in links {
    if let Some(hash) = link.target.into_action_hash() {
      if let Some(record) = get(hash, GetOptions::default())? {
        records.push(record);
      }
    }
  }

  // Action timestamps, not link order: links from two authorities can arrive in any order.
  records.sort_by_key(|record| record.action().timestamp());

  Ok(records)
}

/// Fetch messages by hash, so both read paths below feed one renderer.
#[hdk_extern]
pub fn get_messages(action_hashes: Vec<ActionHash>) -> ExternResult<Vec<Record>> {
  let mut records = Vec::with_capacity(action_hashes.len());

  for hash in action_hashes {
    if let Some(record) = get(hash, GetOptions::default())? {
      records.push(record);
    }
  }

  Ok(records)
}

/// The paginating read: message hashes filed under the given buckets.
///
/// A bucket's contents are validated twice over. `validate_message` pins each entry's bucket
/// to its action timestamp, and `validate_message_link` pins each link's base to the entry's
/// bucket, so a message cannot be filed under a window it does not belong to. What this read
/// cannot detect is a message never linked at all, which is what the chain read below is for.
#[hdk_extern]
pub fn get_message_hashes_in_buckets(buckets: Vec<u32>) -> ExternResult<Vec<ActionHash>> {
  let mut hashes = Vec::new();

  for bucket in buckets {
    let path_hash = messages_path(bucket).path_entry_hash()?;
    let link_type_filter = LinkTypes::PathToMessage
      .try_into_filter()
      .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.to_string())))?;

    // Network, not Local: a participant needs the other participant's messages, which are
    // not on their own chain.
    let links = get_links(
      LinkQuery::new(path_hash, link_type_filter),
      GetStrategy::Network,
    )?;

    for link in links {
      if let Some(hash) = link.target.into_action_hash() {
        hashes.push(hash);
      }
    }
  }

  Ok(hashes)
}

/// One participant's chain, as some authority sees it.
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerChain {
  pub peer: AgentPubKey,

  /// `(action_sequence, action_hash)` for this peer's message entries, in chain order.
  pub messages: Vec<(u32, ActionHash)>,

  /// Passed through unshaped. Every warrant on this stack is a `ChainIntegrity` breach
  /// (`holochain_zome_types-0.6.1/src/warrant.rs` line 87), self-proving and signed by the
  /// authority that found it, so there is no benign category to filter out and nothing to be
  /// gained by modelling it here. What a member is told about one is a governance decision,
  /// not this zome's.
  pub warrants: Vec<SignedWarrant>,

  /// Carries fork evidence, which in a two-party conversation is a signal in its own right.
  pub status: ChainStatus,
}

/// The authoritative read: every message on every participant's chain.
///
/// A source chain is hash-linked and validated, so a participant cannot omit their own
/// entries from it. That makes this, not the bucket index, the complete set: the index can
/// only be incomplete, never lying, because the two validators above pin what a link may say.
/// Comparing the two reads therefore detects the one suppression the index cannot: a message
/// committed and never linked.
///
/// Not an administrator function. An honest participant's own client must see the same set a
/// dispute would surface, or suppression stays invisible until it is contested.
///
/// `get_agent_activity` returns one authority's view, so two callers may legitimately differ
/// while gossip settles. Treat a discrepancy as a signal to re-read, not as proof.
#[hdk_extern]
pub fn get_conversation_chains() -> ExternResult<Vec<PeerChain>> {
  let props = conversation_properties()?;
  let mut chains = Vec::with_capacity(props.peers.len());

  let entry_type: EntryType = UnitEntryTypes::Message.try_into()?;

  for peer in props.peers {
    let activity = get_agent_activity(
      peer.clone(),
      ChainQueryFilter::new().entry_type(entry_type.clone()),
      ActivityRequest::Full,
      GetOptions::default(),
    )?;

    chains.push(PeerChain {
      peer,
      messages: activity.valid_activity,
      warrants: activity.warrants,
      status: activity.status,
    });
  }

  Ok(chains)
}
