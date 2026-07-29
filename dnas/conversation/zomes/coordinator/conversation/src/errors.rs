use hdk::prelude::{wasm_error, SerializedBytesError, WasmError, WasmErrorInner};
use thiserror::Error;

/// Local to this DNA rather than `utils::errors::CommonError`.
///
/// `utils` was the obvious choice and is the wrong one. It exports `DnaProperties`
/// (`dnas/requests_and_offers/utils/src/dna_properties.rs` line 6), typed for the shared
/// DNA's `progenitor_pubkey: Option<String>` and read through
/// `DnaProperties::get_progenitor_pubkey` (`utils/src/lib.rs` line 17). This DNA's
/// properties are `progenitor: AgentPubKey` plus `conversation_id`, so depending on `utils`
/// would put a wrong-shaped properties reader in scope in a DNA it cannot read. That is a
/// trap laid for whoever touches this next, and it costs about ten lines to avoid.
///
/// The `image` crate (`utils/Cargo.toml`) is a secondary consideration only. It is a real
/// dependency, referenced at `utils/src/lib.rs` lines 12 and 126, so whether the linker
/// drops it from a wasm that never calls `is_image` is unmeasured. Size was never the
/// disqualifying argument.
///
/// Message strings below deliberately match `CommonError`'s wording, so anything matching
/// on rendered error text behaves identically across the two DNAs.
#[derive(Debug, Error)]
pub enum ConversationError {
  #[error("Serialization error: {0}")]
  Serialize(SerializedBytesError),

  #[error("Entry not found: {0}")]
  EntryNotFound(String),

  #[error("Record not found: {0}")]
  RecordNotFound(String),

  #[error("Link not found: {0}")]
  LinkNotFound(String),

  #[error("Path error: {0}")]
  PathError(String),

  #[error("Invalid data: {0}")]
  InvalidData(String),

  #[error("Not the author")]
  NotAuthor,

  /// No `CommonError` equivalent. The shared DNA has one progenitor for the whole network;
  /// a conversation clone has one per conversation, and it is the member who started it.
  #[error("Only the conversation's progenitor may issue membrane proofs")]
  NotProgenitor,

  /// No `CommonError` equivalent. See `conversation_properties` in `lib.rs`.
  #[error("This cell holds no conversation")]
  NotAConversation,
}

impl From<ConversationError> for WasmError {
  fn from(err: ConversationError) -> Self {
    wasm_error!(WasmErrorInner::Guest(err.to_string()))
  }
}
