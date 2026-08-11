//! A coordinator that writes what the production coordinator cannot.
//!
//! Each function commits exactly one violation and leaves everything else valid, because
//! `get_invalid_integrated_ops` reports that an op was rejected without saying why. One violation
//! per call means there is only one rule the op can have tripped.

use conversation_integrity::*;
use hdk::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct MisfiledLinkInput {
  /// A message committed honestly, by this agent or the other participant.
  pub message_hash: ActionHash,

  /// The bucket to file it under, which is not the one the message belongs to.
  pub wrong_bucket: u32,
}

/// Link an honest message from the wrong bucket's path.
///
/// The production coordinator derives both the message's bucket and its link base from one value,
/// so it cannot produce this. A participant who wanted their own messages absent from the index an
/// invited administrator walks would write exactly this.
#[hdk_extern]
pub fn create_misfiled_link(input: MisfiledLinkInput) -> ExternResult<ActionHash> {
  create_link(
    messages_path(input.wrong_bucket).path_entry_hash()?,
    input.message_hash,
    LinkTypes::PathToMessage,
    (),
  )
}

/// Delete a link this agent did not create.
///
/// Holochain does not require the author of a delete-link action to be the author of the link it
/// deletes. Deleting the other participant's message links empties the thread index for every
/// reader, which suppresses their messages rather than hiding one's own.
#[hdk_extern]
pub fn delete_any_link(create_link_hash: ActionHash) -> ExternResult<ActionHash> {
  // Network, because the link being deleted was authored by the other participant.
  delete_link(create_link_hash, GetOptions::network())
}

/// Commit a message whose bucket does not match its own action timestamp.
///
/// The production coordinator derives the bucket from the clock, so only a modified one can claim
/// a message belongs to a window it was not sent in.
#[hdk_extern]
pub fn create_mistimed_message(bucket: u32) -> ExternResult<ActionHash> {
  create_entry(EntryTypes::Message(Message {
    content: "committed with a bucket that does not match its timestamp".to_string(),
    message_type: MessageType::Text,
    reply_to: None,
    bucket,
  }))
}

/// Read the link this agent created for a message, so a test can name it for deletion by another
/// agent. Not itself hostile; it exists because the production coordinator returns message hashes
/// rather than link hashes.
#[hdk_extern]
pub fn get_message_link_hashes(bucket: u32) -> ExternResult<Vec<ActionHash>> {
  let link_type_filter = LinkTypes::PathToMessage
    .try_into_filter()
    .map_err(|e| wasm_error!(WasmErrorInner::Guest(e.to_string())))?;

  let links = get_links(
    LinkQuery::new(messages_path(bucket).path_entry_hash()?, link_type_filter),
    // Local, not Network: after a restart this node has no peers, and the link is on this
    // agent's own chain anyway.
    GetStrategy::Local,
  )?;

  Ok(links.into_iter().map(|link| link.create_link_hash).collect())
}
