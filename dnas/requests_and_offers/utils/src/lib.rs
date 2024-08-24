use hdk::prelude::*;
use WasmErrorInner::*;
pub mod dna_properties;

pub use dna_properties::DnaProperties;

pub fn check_if_progenitor() -> ExternResult<bool> {
  let progenitor_pubkey = DnaProperties::get_progenitor_pubkey()?;

  Ok(progenitor_pubkey == agent_info()?.agent_initial_pubkey)
}

pub fn get_original_record(original_action_hash: ActionHash) -> ExternResult<Option<Record>> {
  let Some(details) = get_details(original_action_hash, GetOptions::default())? else {
    return Ok(None);
  };

  match details {
    Details::Record(details) => Ok(Some(details.record)),
    _ => Err(wasm_error!(Guest(
      "Malformed get details response".to_string()
    ))),
  }
}

pub fn get_all_revisions_for_entry(
  original_action_hash: ActionHash,
  link_types: impl LinkTypeFilterExt,
) -> ExternResult<Vec<Record>> {
  let Some(original_record) = get_original_record(original_action_hash.clone())? else {
    return Ok(vec![]);
  };

  let links = get_links(original_action_hash.clone(), link_types, None)?;

  let records: Vec<Option<Record>> = links
    .into_iter()
    .map(|link| {
      get(
        link.target.into_action_hash().ok_or(wasm_error!(Guest(
          "No action hash associated with link".to_string()
        )))?,
        GetOptions::default(),
      )
    })
    .collect::<ExternResult<Vec<Option<Record>>>>()?;
  let mut records: Vec<Record> = records.into_iter().flatten().collect();
  records.insert(0, original_record);

  Ok(records)
}
