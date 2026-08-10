//! Conversation membrane tests.
//!
//! The conversation role is provisioned directly with real properties rather than
//! cloned, because that is the shortest path to exercising `check_agent` at genesis.
//! The clone lifecycle is a separate concern with its own harness.

use holochain::sweettest::*;
use requests_and_offers_sweettest::common::*;

const CONVERSATION_ID: &str = "test-conversation-0001";

#[tokio::test(flavor = "multi_thread")]
async fn peer_is_admitted_without_a_membrane_proof() {
    let conductor = SweetConductor::from_standard_config().await;
    let (alice, bob) = SweetAgents::two(conductor.keystore()).await;

    let peers = ordered_peers(&[alice.clone(), bob.clone()]);
    let props = conversation_properties(&peers, CONVERSATION_ID);

    let installed = install_with_conversation(&conductor, props, None, Some(alice.clone()))
        .await
        .expect("installing with alice as a listed peer should succeed");

    assert_eq!(
        installed.role_assignments().len(),
        3,
        "expected the three roles from happ.yaml"
    );
}
