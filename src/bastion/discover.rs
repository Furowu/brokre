use crate::bastion::model::{BastionListItem, ListItemKind};
use crate::bastion::probe::{probe_items, ProbeOptions};
use crate::bastion::registry::{list_bastions, max_bastions};
use crate::bastion::session::ensure_gate_for_outbound;
use crate::bastion::transport::run_remote_list_json_probe;
use crate::utils::errors::{BrokreError, Result};
use crate::vault::model::SecretRecord;

pub struct DiscoverOptions {
    pub probe: bool,
    pub include_bastions: bool,
}

pub fn discover_remote_items(opts: &DiscoverOptions) -> Result<Vec<BastionListItem>> {
    if !opts.include_bastions {
        return Ok(vec![]);
    }
    ensure_gate_for_outbound()?;
    let bastions = list_bastions()?;
    if bastions.is_empty() {
        return Ok(vec![]);
    }
    let limit = max_bastions();
    let mut out = Vec::new();
    for entry in bastions.into_iter().take(limit) {
        match fetch_bastion_items(&entry.alias, opts.probe) {
            Ok(mut items) => out.append(&mut items),
            Err(e) => {
                out.push(BastionListItem {
                    profile: "bastion".into(),
                    name: entry.alias.clone(),
                    addr: entry.alias.clone(),
                    route: vec![],
                    kind: ListItemKind::Bastion,
                    host_alias: entry.host_alias.clone(),
                    labels: vec![],
                    created_at: Some(entry.enabled_at),
                    last_used_at: None,
                    status: Some(crate::bastion::model::ProbeStatus {
                        reachable: false,
                        probe_ms: None,
                        checked_at: chrono::Utc::now().to_rfc3339(),
                        error: Some(e.to_string()),
                        source: "local".into(),
                    }),
                });
            }
        }
    }
    Ok(out)
}

fn fetch_bastion_items(bastion_alias: &str, probe: bool) -> Result<Vec<BastionListItem>> {
    let stdout = run_remote_list_json_probe(bastion_alias)?;
    let mut items: Vec<BastionListItem> = serde_json::from_str(&stdout)
        .map_err(|e| BrokreError::Runtime(format!("parse remote list from {bastion_alias}: {e}")))?;
    for item in &mut items {
        if item.kind == ListItemKind::Local {
            item.kind = ListItemKind::Inner;
        }
        if item.route.is_empty() {
            item.route = vec![bastion_alias.to_string()];
        }
        if !item.addr.contains("::") {
            item.addr = format!("{bastion_alias}::{}", item.name);
        }
        if let Some(ref mut status) = item.status {
            status.source = bastion_alias.to_string();
        }
    }
    if probe {
        // Remote list already probed on bastion; keep status as-is.
    }
    Ok(items)
}

pub fn build_local_items(
    records: Vec<SecretRecord>,
    probe: bool,
) -> Result<Vec<BastionListItem>> {
    let mut items: Vec<BastionListItem> = records
        .into_iter()
        .map(|r| BastionListItem::from_local_record(&r))
        .collect();
    if probe {
        let opts = ProbeOptions::default();
        probe_items(&mut items, &opts)?;
    }
    Ok(items)
}

pub fn merge_list_items(mut local: Vec<BastionListItem>, remote: Vec<BastionListItem>) -> Vec<BastionListItem> {
    local.extend(remote);
    local
}
