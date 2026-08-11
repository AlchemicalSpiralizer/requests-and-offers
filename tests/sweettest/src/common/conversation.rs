//! Conductor setup for the conversation DNA.
//!
//! Separate from `conductors.rs` because that module installs a single DNA via
//! `SweetConductor::setup_app`, which hardcodes `None` for every membrane proof
//! (`holochain-0.6.1/src/sweettest/sweet_conductor.rs` line 323, an upstream TODO,
//! unchanged in 0.6.3 and 0.7.0). The conversation DNA gates genesis on a proof, so
//! it needs `ConductorHandle::install_app_bundle`, which is public and takes a
//! per-role `RoleSettings::Provisioned { membrane_proof, modifiers }`.

use holochain::conductor::api::error::ConductorApiError;
use holochain::conductor::error::ConductorResult;
use holochain::prelude::*;
use holochain::sweettest::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Path to the packed hApp bundle. `bun run build:happ` must have been run.
pub const HAPP_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../workdir/requests_and_offers.happ"
);

/// The conversation role name in `workdir/happ.yaml`.
pub const CONVERSATION_ROLE: &str = "conversation";

/// Mirror of `Properties` from `conversation_integrity`.
///
/// Mirrored rather than imported: each integrity crate emits C-level
/// `__num_entry_types` / `__num_link_types` symbols that collide when two are linked
/// into one binary (see `mirrors.rs`).
///
/// Keys are base64 strings here because the conductor takes properties as
/// `YamlProperties` and converts to msgpack, which the zome then reads as typed
/// `AgentPubKey`. This is the shape Volla uses in production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationProperties {
    pub peers: Vec<String>,
    pub conversation_id: String,

    /// Base64 like `peers`, for the same reason: the conductor takes YAML and the zome
    /// reads a typed `ActionHash` back. Proven for `AgentPubKey`; this exercises the same
    /// `HoloHash` path with a different prefix.
    pub context_hash: Option<String>,

    /// `Request`, `Offer` or `Direct`, matching the zome's `ContextType` variant names.
    pub context_type: String,

    pub start_bucket: u32,
}

/// Mirror of `MembraneProofData`.
#[derive(Debug, Clone, Serialize, Deserialize, SerializedBytes)]
pub struct MembraneProofData {
    pub conversation_id: String,
    pub for_agent: AgentPubKey,
    pub signer: AgentPubKey,
}

/// Mirror of `MembraneProofEnvelope`.
#[derive(Debug, Clone, Serialize, Deserialize, SerializedBytes)]
pub struct MembraneProofEnvelope {
    pub signature: Signature,
    pub data: MembraneProofData,
}

/// Sort keys as the integrity zome requires: ascending and distinct.
pub fn ordered_peers(keys: &[AgentPubKey]) -> Vec<AgentPubKey> {
    let mut out = keys.to_vec();
    out.sort();
    out.dedup();
    out
}

/// Build conversation properties from the peer list exactly as given, including an
/// order the integrity zome will refuse. For tests that exercise the ordering guard.
pub fn conversation_properties_unchecked(
    peers: &[AgentPubKey],
    conversation_id: &str,
) -> YamlProperties {
    conversation_properties_full(peers, conversation_id, None, "Direct", 0)
}

/// Build conversation properties for a peer set, sorted as the zome requires.
///
/// Defaults to a Direct conversation with no context hash, which satisfies the zome's
/// `Direct` implies no-context invariant, and to bucket zero, which no message can precede.
pub fn conversation_properties(
    peers: &[AgentPubKey],
    conversation_id: &str,
) -> YamlProperties {
    conversation_properties_unchecked(&ordered_peers(peers), conversation_id)
}

/// Build properties for a conversation about a listing. Sorts the peer set.
pub fn conversation_properties_with_context(
    peers: &[AgentPubKey],
    conversation_id: &str,
    context_hash: &ActionHash,
    context_type: &str,
    start_bucket: u32,
) -> YamlProperties {
    conversation_properties_full(
        &ordered_peers(peers),
        conversation_id,
        Some(context_hash.to_string()),
        context_type,
        start_bucket,
    )
}

/// Every field explicit, including combinations the zome refuses. Peers are taken exactly
/// as given so the ordering guard stays testable.
pub fn conversation_properties_full(
    peers: &[AgentPubKey],
    conversation_id: &str,
    context_hash: Option<String>,
    context_type: &str,
    start_bucket: u32,
) -> YamlProperties {
    let props = ConversationProperties {
        peers: peers.iter().map(|k| k.to_string()).collect(),
        conversation_id: conversation_id.to_string(),
        context_hash,
        context_type: context_type.to_string(),
        start_bucket,
    };

    YamlProperties::new(serde_yaml::to_value(props).expect("properties should serialise to YAML"))
}

/// Panic if the packed bundle predates any zome source, naming the fix.
///
/// `HAPP_PATH` is read from disk with no freshness check, so a bundle built before the source
/// it is meant to contain fails later and unhelpfully: a missing extern surfaces as
/// `ZomeFnNotExists`, which reads as a code bug rather than a stale artefact. This turns that
/// into an instruction.
fn assert_bundle_is_current() {
    let bundle = std::fs::metadata(HAPP_PATH)
        .and_then(|m| m.modified())
        .expect("the packed bundle should exist; run bun run build:happ");

    let dnas = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dnas");
    let mut newest: Option<(std::path::PathBuf, std::time::SystemTime)> = None;

    let mut stack = vec![dnas];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // `target` holds build output, which is newer than the bundle by construction.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs" || e == "yaml") {
                if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().is_none_or(|(_, t)| modified > *t) {
                        newest = Some((path, modified));
                    }
                }
            }
        }
    }

    if let Some((path, modified)) = newest {
        assert!(
            bundle >= modified,
            "the packed bundle is older than {}.\n  run: bun run build:happ",
            path.display()
        );
    }
}

/// Install the hApp on `conductor`, provisioning the conversation role with the given
/// properties and optional membrane proof.
///
/// `ignore_genesis_failure` is set so a refused proof leaves the app installed with
/// empty cells rather than uninstalling it, which makes the refusal observable.
pub async fn install_with_conversation(
    conductor: &SweetConductor,
    properties: YamlProperties,
    membrane_proof: Option<MembraneProof>,
    agent: Option<AgentPubKey>,
) -> ConductorResult<InstalledApp> {
    assert_bundle_is_current();

    let mut roles_settings: RoleSettingsMap = HashMap::new();
    roles_settings.insert(
        CONVERSATION_ROLE.to_string(),
        RoleSettings::Provisioned {
            membrane_proof,
            modifiers: Some(DnaModifiersOpt::default().with_properties(properties)),
        },
    );

    conductor
        .raw_handle()
        .install_app_bundle(InstallAppPayload {
            source: AppBundleSource::Path(std::path::PathBuf::from(HAPP_PATH)),
            agent_key: agent,
            installed_app_id: Some("requests_and_offers".to_string()),
            network_seed: None,
            roles_settings: Some(roles_settings),
            ignore_genesis_failure: true,
        })
        .await
}

/// Enable the app and hand back a callable handle on the conversation coordinator zome.
///
/// `install_with_conversation` installs but does not enable, and a disabled app has no running
/// cell to call. The cell id is built rather than read: `AppRolePrimary` records the role's
/// `base_dna_hash` and the agent is always the one the app was installed for, so those two
/// compose into the `CellId`.
pub async fn enable_conversation_zome(
    conductor: &SweetConductor,
    installed: &InstalledApp,
    agent: &AgentPubKey,
) -> SweetZome {
    conductor
        .raw_handle()
        .enable_app(installed.installed_app_id.clone())
        .await
        .expect("enabling the installed app should succeed");

    let primary = installed
        .role_assignments()
        .get(CONVERSATION_ROLE)
        .expect("happ.yaml should declare a conversation role")
        .as_primary()
        .expect("the conversation role is provisioned by this app, not a dependency");

    let cell_id = CellId::new(primary.base_dna_hash.clone(), agent.clone());

    SweetZome::new(cell_id, CONVERSATION_ROLE.into())
}

/// Assert a zome call was refused, and refused for the expected reason.
///
/// Separate from `assert_refused`: that one reads a genesis failure from an install, where a
/// refused zome call surfaces validation text through a different error type.
pub fn assert_call_refused<T: std::fmt::Debug>(
    result: Result<T, ConductorApiError>,
    expected: &str,
) {
    match result {
        Ok(value) => panic!("expected the call to be refused, but it returned {value:?}"),
        Err(err) => {
            let text = format!("{err:?}");
            assert!(
                text.contains(expected),
                "refused, but not for the expected reason.\n  expected: {expected}\n  actual: {text}"
            );
        }
    }
}

/// Assert an install was refused, and refused for the expected reason.
///
/// Validation messages reach the caller intact inside
/// `GenesisFailed -> WorkflowError -> GenesisFailure`, so a substring match is enough.
pub fn assert_refused<T>(result: ConductorResult<T>, expected: &str) {
    match result {
        Ok(_) => panic!("expected genesis to be refused, but the install succeeded"),
        Err(err) => {
            let text = format!("{err:?}");
            assert!(
                text.contains(expected),
                "refused, but not for the expected reason.\n  expected: {expected}\n  actual: {text}"
            );
        }
    }
}

/// Sign a membrane proof admitting `for_agent`, as `issue_membrane_proof` does.
pub async fn issue_proof(
    conductor: &SweetConductor,
    signer: &AgentPubKey,
    for_agent: &AgentPubKey,
    conversation_id: &str,
) -> MembraneProof {
    let data = MembraneProofData {
        conversation_id: conversation_id.to_string(),
        for_agent: for_agent.clone(),
        signer: signer.clone(),
    };

    // The keystore signs raw bytes. The zome's `sign(key, data)` serialises the struct
    // to msgpack via SerializedBytes first, so this must do the same or the signature
    // will not verify inside the DNA.
    let bytes = SerializedBytes::try_from(data.clone()).expect("proof data should serialise");
    let signature = conductor
        .raw_handle()
        .keystore()
        .sign(signer.clone(), bytes.bytes().to_vec().into())
        .await
        .expect("signing should succeed");

    let envelope = MembraneProofEnvelope { signature, data };

    Arc::new(SerializedBytes::try_from(envelope).expect("envelope should serialise"))
}
