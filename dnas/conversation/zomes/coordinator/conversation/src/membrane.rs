use conversation_integrity::*;
use hdk::prelude::*;
use utils::errors::CommonError;

use crate::conversation_properties;
use crate::errors::ConversationError;
use crate::messages::commit_message;

#[derive(Serialize, Deserialize, Debug)]
pub struct AdminInvitation {
  /// Announced in the conversation before the proof was issued.
  pub notice: ActionHash,

  /// The membrane proof admitting the administrator, to be delivered to them.
  pub proof: SerializedBytes,
}

/// Invite an administrator into this conversation, announcing it first.
///
/// Note section 10 requires the announcement to be a committed entry rather than a client-side
/// rendering, so that a modified client cannot suppress it. The commit therefore happens here
/// and before the proof exists: if the commit fails the caller gets no proof, so there is no
/// path to an admitted administrator with no notice. The reverse order would leave one.
///
/// Unilateral by design. Requiring the other participant's agreement would defeat the
/// instrument in the case that most needs it, since a participant behaving badly will not
/// consent to being observed. The notice is the safeguard.
///
/// An invited administrator reads the conversation's whole history, from both participants,
/// not merely what follows their arrival. That is what the consent wording must convey, and
/// the wording is a governance matter.
#[hdk_extern]
pub fn invite_admin(admin: AgentPubKey) -> ExternResult<AdminInvitation> {
  let props = conversation_properties()?;
  let me = agent_info()?.agent_initial_pubkey;

  if !props.peers.contains(&me) {
    return Err(ConversationError::NotAParticipant.into());
  }

  if props.peers.contains(&admin) {
    return Err(ConversationError::AlreadyAParticipant.into());
  }

  let notice = commit_message(
    String::new(),
    MessageType::System(SystemEvent::AdminInvited {
      admin: admin.clone(),
    }),
    None,
  )?
  .action_address()
  .clone();

  Ok(AdminInvitation {
    notice,
    proof: issue_membrane_proof(admin)?,
  })
}

/// Issue a membrane proof admitting `for_agent` to this conversation clone.
///
/// Only for agents not named in the clone's properties, which in this design means an
/// invited administrator: participants are admitted by identity and need no proof.
///
/// Mirrors Volla's `generate_membrane_proof`
/// (`_reference/volla-messages/dnas/relay/zomes/coordinator/relay/src/lib.rs` line 257):
/// sign the data struct, wrap it, serialise. Signing over the struct rather than raw bytes
/// means `sign` here and `verify_signature` in `check_agent` serialise through one
/// mechanism and cannot drift apart. Do not add a byte-encoding helper.
///
/// `conversation_id` is read from `dna_info()` rather than taken as input, as Volla does:
/// a caller-supplied id that mismatched would produce a proof rejected at the recipient's
/// genesis, with nothing surfacing to the issuer.
///
/// Not an `hdk_extern`. Issuing a proof without announcing it would defeat note section 10,
/// so `invite_admin` is the only route in.
pub fn issue_membrane_proof(for_agent: AgentPubKey) -> ExternResult<SerializedBytes> {
  let props = conversation_properties()?;
  let me = agent_info()?.agent_initial_pubkey;

  if !props.peers.contains(&me) {
    return Err(ConversationError::NotAParticipant.into());
  }

  let data = MembraneProofData {
    conversation_id: props.conversation_id,
    for_agent,
    signer: me.clone(),
  };

  let envelope = MembraneProofEnvelope {
    signature: sign(me, data.clone())?,
    data,
  };

  SerializedBytes::try_from(envelope).map_err(|e| CommonError::Serialize(e).into())
}
