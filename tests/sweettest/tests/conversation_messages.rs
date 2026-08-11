//! Message validation tests that need a running cell.
//!
//! Unlike the genesis-time tests, these install, enable and then call the coordinator, so they
//! assert what the zome refuses to commit rather than what it refuses to admit.

use holochain::prelude::*;
use holochain::sweettest::*;
use requests_and_offers_sweettest::common::*;
use serde::{Deserialize, Serialize};

const CONVERSATION_ID: &str = "test-conversation-0003";

/// Mirror of `CreateMessageInput` from the conversation coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CreateMessageInput {
    content: String,
    reply_to: Option<ActionHash>,
}

/// Far enough ahead that no honest message can reach it: at thirty-day windows, bucket 2000 is
/// roughly a century and a half from the epoch.
const FUTURE_START_BUCKET: u32 = 2000;

/// A message below the conversation's declared start is refused.
///
/// The floor exists so a joining agent, in particular an invited administrator reading the whole
/// history, has somewhere to walk forward from. Because `create_message` derives the bucket from
/// the clock, the only way to produce a message below the floor through the coordinator is to
/// declare a start in the future, which is what this does. That makes the properties absurd
/// rather than the message malicious; a real message hidden beneath an honest floor cannot be
/// built through this coordinator at all, and needs a test that writes to a source chain
/// directly.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_below_the_start_bucket_is_refused() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_full(
        &peers,
        CONVERSATION_ID,
        None,
        "Direct",
        FUTURE_START_BUCKET,
    );

    let installed = install_with_conversation(&conductor, props, None, Some(alice.clone()))
        .await
        .expect("a future start bucket is not itself invalid, so genesis should succeed");

    let zome = enable_conversation_zome(&conductor, &installed, &alice).await;

    let result: Result<Record, _> = conductor
        .call_fallible(
            &zome,
            "create_message",
            CreateMessageInput {
                content: "sent before this conversation claims to have started".to_string(),
                reply_to: None,
            },
        )
        .await;

    assert_call_refused(result, "precedes the conversation start bucket");
}

/// The same conversation with a start bucket in the past accepts a message, so the refusal above
/// is the floor firing rather than the commit path being broken.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_at_or_above_the_start_bucket_is_committed() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_full(&peers, CONVERSATION_ID, None, "Direct", 0);

    let installed = install_with_conversation(&conductor, props, None, Some(alice.clone()))
        .await
        .expect("installing with alice as a listed peer should succeed");

    let zome = enable_conversation_zome(&conductor, &installed, &alice).await;

    let record: Record = conductor
        .call(
            &zome,
            "create_message",
            CreateMessageInput {
                content: "the first thing said".to_string(),
                reply_to: None,
            },
        )
        .await;

    assert!(
        record.action().entry_hash().is_some(),
        "the committed record should carry a message entry"
    );
}
