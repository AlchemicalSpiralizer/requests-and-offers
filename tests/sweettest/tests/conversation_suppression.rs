//! Suppression and forgery tests, run through a hostile coordinator.
//!
//! The production coordinator cannot produce these writes: it derives a message's bucket from the
//! clock and its link base from that bucket, so entry and index always agree. A participant
//! running a modified coordinator can, and that is the threat these validators exist for.
//!
//! Holochain computes the DNA hash over integrity zomes and modifiers only, so the swap keeps the
//! same DNA, the same network and the same validation. Every hostile write goes through the
//! ordinary commit path, which is why the workflows run and a rejection is observable.
//!
//! Each test plants exactly one violation. `get_invalid_integrated_ops` says an op was rejected
//! without saying why, so leaving everything else valid is what makes the assertion meaningful.

use holochain::prelude::*;
use holochain::sweettest::*;
use requests_and_offers_sweettest::common::*;
use serde::{Deserialize, Serialize};

const CONVERSATION_ID: &str = "test-conversation-0004";

/// The bucket a message committed now belongs to. Mirrors `bucket_from_timestamp` in the integrity
/// crate, which the test crate cannot import: linking two integrity crates collides their C-level
/// entry and link type symbols.
fn current_bucket() -> u32 {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock should be after the epoch")
        .as_micros() as i64;

    (micros / (30 * 24 * 60 * 60 * 1_000_000)) as u32
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateMessageInput {
    content: String,
    reply_to: Option<ActionHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MisfiledLinkInput {
    message_hash: ActionHash,
    wrong_bucket: u32,
}

/// Install, enable, and commit one honest message before anything hostile happens, which is also
/// how a real bad actor behaves: ordinarily, until they do not.
async fn conversation_with_one_message(
    conductor: &SweetConductor,
) -> (CellId, ActionHash, AgentPubKey, InstalledAppId) {
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_full(&peers, CONVERSATION_ID, None, "Direct", 0);

    let installed = install_with_conversation(conductor, props, None, Some(alice.clone()))
        .await
        .expect("installing with alice as a listed peer should succeed");

    let zome = enable_conversation_zome(conductor, &installed, &alice).await;

    let honest: Record = conductor
        .call(
            &zome,
            "create_message",
            CreateMessageInput {
                content: "an ordinary message".to_string(),
                reply_to: None,
            },
        )
        .await;

    (
        zome.cell_id().clone(),
        honest.action_address().clone(),
        alice,
        installed.installed_app_id.clone(),
    )
}

/// A message linked from a bucket it does not belong to is rejected.
///
/// The base is derivable from the message's own validated bucket, so a base that disagrees carries
/// no information and can only mislead. Left unchecked, a participant could commit correctly
/// bucketed messages while filing the links under a bucket nobody walks, and an administrator
/// invited to read the whole history would find the other participant's messages and not theirs.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_link_filed_under_the_wrong_bucket_is_rejected() {
    let mut conductor = SweetConductor::from_standard_config().await;
    let (cell_id, message_hash, _alice, _app_id) = conversation_with_one_message(&conductor).await;

    let hostile = swap_in_hostile_coordinator(&mut conductor, cell_id).await;

    let result: Result<ActionHash, _> = conductor
        .call_fallible(
            &hostile,
            "create_misfiled_link",
            MisfiledLinkInput {
                message_hash,
                wrong_bucket: 999,
            },
        )
        .await;

    // Refused at commit time rather than after integration: the author's own node self-validates
    // before the op is stored, so the reason reaches the caller intact.
    assert_call_refused(result, "must be linked from that bucket's path");
}

/// A message whose bucket does not match its own action timestamp is rejected.
///
/// The bucket decides whether a message is found, so a client free to choose it could place its
/// messages outside any window the other participant fetches.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_bucketed_against_the_wrong_window_is_rejected() {
    let mut conductor = SweetConductor::from_standard_config().await;
    let (cell_id, _, _alice, _app_id) = conversation_with_one_message(&conductor).await;

    let hostile = swap_in_hostile_coordinator(&mut conductor, cell_id).await;

    // Above the start bucket, so the floor cannot be what refuses this: only the timestamp check
    // can.
    let result: Result<ActionHash, _> = conductor
        .call_fallible(&hostile, "create_mistimed_message", 999u32)
        .await;

    assert_call_refused(result, "does not match the bucket its timestamp falls in");
}

/// No link in a conversation may be deleted, by anyone, including the agent who created it.
///
/// A link delete is an appended action rather than an erasure, but a tombstoned link stops being
/// returned by `get_links`, so deleting one removes a message from the index while the entry stays
/// on its author's chain. An invited administrator walking the index would not find it.
///
/// Restricting deletes to the link's author would have licensed exactly that, for one's own
/// messages, which is the outcome the misfiled-link guard exists to prevent. Retracting something
/// said is an edit within its window or a client-side marker, never a change to what the index
/// reports.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_link_cannot_be_deleted() {
    let mut conductor = SweetConductor::from_standard_config().await;
    let (cell_id, _, _alice, _app_id) = conversation_with_one_message(&conductor).await;

    let hostile = swap_in_hostile_coordinator(&mut conductor, cell_id).await;

    let bucket = current_bucket();

    let link_hashes: Vec<ActionHash> = conductor
        .call(&hostile, "get_message_link_hashes", bucket)
        .await;

    assert_eq!(
        link_hashes.len(),
        1,
        "the honest message should have left exactly one link"
    );

    let result: Result<ActionHash, _> = conductor
        .call_fallible(&hostile, "delete_any_link", link_hashes[0].clone())
        .await;

    assert_call_refused(result, "links are not deletable in a conversation");
}
