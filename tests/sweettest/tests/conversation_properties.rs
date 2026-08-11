//! Conversation properties tests.
//!
//! Creation-time context lives in the clone's DNA properties rather than on an entry, so these
//! assert at genesis. Properties feed the DNA hash, which means a malformed context cannot be
//! corrected after the fact: refusing at genesis is the only place the check can be made.

use holochain::prelude::*;
use holochain::sweettest::*;
use requests_and_offers_sweettest::common::*;

const CONVERSATION_ID: &str = "test-conversation-0002";

/// A hash nothing resolves, which is the point: the listing it names lives in the shared DNA
/// and is resolved frontend-side, never fetched here.
///
/// `from_raw_32` rather than `from_raw_36`: the last four bytes of a `HoloHash` are a checksum
/// over the first thirty-two, so supplying all thirty-six by hand fails with `BadChecksum` on
/// the way back in.
fn listing_hash() -> ActionHash {
    ActionHash::from_raw_32(vec![7u8; 32])
}

/// Properties reach the zome as base64 in YAML and are read back as a typed `ActionHash`. That
/// path was proven for `Vec<AgentPubKey>` by the membrane tests and only inferred for
/// `ActionHash`, which is a different hash prefix through the same machinery.
///
/// A successful install is the assertion. `check_agent` deserialises the whole `Properties`
/// struct before it checks anything, so a hash that failed to round-trip would refuse genesis.
#[tokio::test(flavor = "multi_thread")]
async fn a_context_hash_round_trips_through_yaml_properties() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_with_context(
        &peers,
        CONVERSATION_ID,
        &listing_hash(),
        "Request",
        0,
    );

    let installed = install_with_conversation(&conductor, props, None, Some(alice.clone()))
        .await
        .expect("a typed context hash in properties should deserialise and admit a peer");

    assert_eq!(
        installed.role_assignments().len(),
        3,
        "expected the three roles from happ.yaml"
    );
}

/// A direct conversation concerns no listing, so carrying one is incoherent rather than merely
/// unused: the clone would claim a context its type says it does not have.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_conversation_carrying_a_context_hash_is_refused() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_full(
        &peers,
        CONVERSATION_ID,
        Some(listing_hash().to_string()),
        "Direct",
        0,
    );

    let result = install_with_conversation(&conductor, props, None, Some(alice.clone())).await;

    assert_refused(result, "must carry no context hash");
}

/// The other direction. A conversation about a request or an offer must say which one, or the
/// listing it concerns is unrecoverable: nothing else in the clone records it.
#[tokio::test(flavor = "multi_thread")]
async fn a_listing_conversation_without_a_context_hash_is_refused() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties_full(&peers, CONVERSATION_ID, None, "Request", 0);

    let result = install_with_conversation(&conductor, props, None, Some(alice.clone())).await;

    assert_refused(result, "must carry no context hash");
}
