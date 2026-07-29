use hdk::prelude::{wasm_error, WasmError, WasmErrorInner};
use thiserror::Error;

/// Conversation-specific errors only. Anything with a `CommonError` equivalent
/// uses `utils::errors::CommonError` instead.
///
/// This follows the house pattern of a domain enum *alongside* `CommonError`
/// rather than instead of it, as `UsersError`, `OrganizationsError` and
/// `AdministrationError` do in `dnas/requests_and_offers/utils/src/errors.rs`.
///
/// An earlier revision duplicated `CommonError` here to avoid depending on
/// `utils` at all. The reason was that `utils` exports a `DnaProperties` typed
/// for the shared DNA, and serde silently accepted this DNA's properties as a
/// progenitorless read, so a reader reaching for the obvious helper would get a
/// wrong answer that looked like dev mode. That trap is now closed at source by
/// `#[serde(deny_unknown_fields)]`, so the duplication bought nothing and cost
/// real fidelity: `From<CommonError> for WasmError` is a hand-written match that
/// distinguishes `Memory`, `Serialize`, `Deserialize` and `Host`, where a local
/// enum flattens everything to `Guest`.
///
/// Imports of `utils` stay selective, matching every one of the eleven crates
/// that depend on it. There are no glob imports of `utils` anywhere in the
/// repository and there should not be one here.
#[derive(Debug, Error)]
pub enum ConversationError {
  /// `UsersError::NotAuthor` exists but belongs to the users domain in the
  /// shared DNA, and this DNA has no users.
  #[error("Not the author")]
  NotAuthor,

  /// The shared DNA has one progenitor for the whole network. A conversation
  /// clone has one per conversation, and it is the member who started it.
  #[error("Only the conversation's progenitor may issue membrane proofs")]
  NotProgenitor,

  /// See `conversation_properties` in `lib.rs`.
  #[error("This cell holds no conversation")]
  NotAConversation,
}

impl From<ConversationError> for WasmError {
  fn from(err: ConversationError) -> Self {
    wasm_error!(WasmErrorInner::Guest(err.to_string()))
  }
}
