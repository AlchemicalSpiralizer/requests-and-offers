use conversation_integrity::*;
use hdk::prelude::*;

use crate::conversation_properties;
use crate::errors::ConversationError;

/// Issue a membrane proof admitting `for_agent` to this conversation clone.
///
/// The mechanism mirrors Volla's `generate_membrane_proof`
/// (`~/Desktop/claude-workspace/_reference/volla-messages/dnas/relay/zomes/coordinator/relay/src/lib.rs`
/// line 257): sign the data struct, wrap it in the envelope, serialise. The signature is
/// taken over the struct rather than over raw bytes, and `check_agent` verifies it the same
/// way (`dnas/conversation/zomes/integrity/conversation/src/lib.rs` line 102), so the two
/// sides serialise through one mechanism and cannot drift apart. No shared byte-encoding
/// helper is needed or wanted.
///
/// Two divergences from Volla, both closing a path where a caller receives a proof that is
/// already guaranteed to fail somewhere they cannot see.
///
/// First, the input. Volla takes the whole `MembraneProofData`, which lets a caller name any
/// conversation, including one this clone is not. This takes `for_agent` alone and reads
/// `conversation_id` from `dna_info()`, because a mismatched id produces a proof that is
/// rejected at the recipient's genesis with nothing surfacing to the issuer.
///
/// Second, the signer. Volla signs with `agent_info()?.agent_initial_pubkey`
/// unconditionally. The integrity zome verifies against `props.progenitor`, so a
/// non-progenitor caller would emit a proof that no clone will ever accept. Comparing caller
/// to progenitor first turns a silent remote failure into a local error.
///
/// Note that the progenitor never needs a proof for their own clone: `check_agent` admits
/// them by identity at line 78. This function is only ever called for the other party.
#[hdk_extern]
pub fn issue_membrane_proof(for_agent: AgentPubKey) -> ExternResult<SerializedBytes> {
  let props = conversation_properties()?;
  let me = agent_info()?.agent_initial_pubkey;

  if me != props.progenitor {
    return Err(ConversationError::NotProgenitor.into());
  }

  let data = MembraneProofData {
    conversation_id: props.conversation_id,
    for_agent,
  };

  let envelope = MembraneProofEnvelope {
    signature: sign(me, data.clone())?,
    data,
  };

  SerializedBytes::try_from(envelope).map_err(|e| ConversationError::Serialize(e).into())
}
