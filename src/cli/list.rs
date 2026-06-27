use crate::bastion::gate::prepare_outbound_gate_for_list;
use crate::bastion::list_policy::{
    collect_list_items, format_status_display, resolve_list_options, RawListOptions,
};
use crate::bastion::model::BastionListItem;
use crate::utils::errors::Result;
use crate::vault::store::VaultStore;

pub struct ListOptions {
    pub profile_filter: Option<String>,
    pub labels: Vec<String>,
    pub host_glob: Option<String>,
    pub name_glob: Option<String>,
    pub json: bool,
    pub probe: bool,
    pub include_bastions: bool,
    pub no_bastion_discovery: bool,
    /// Show unreachable aliases (disables smart filtering).
    pub show_all: bool,
}

pub fn run(opts: ListOptions) -> Result<()> {
    let store = VaultStore::open()?;
    let mut records = store.list()?;

    if let Some(p) = opts.profile_filter {
        records.retain(|r| r.profile == p);
    }
    if !opts.labels.is_empty() {
        records.retain(|r| opts.labels.iter().all(|l| r.labels.contains(l)));
    }
    if let Some(ref h) = opts.host_glob {
        records.retain(|r| {
            r.host_alias
                .as_ref()
                .map(|a| a.contains(h))
                .unwrap_or(false)
        });
    }
    if let Some(ref n) = opts.name_glob {
        records.retain(|r| r.name.contains(n));
    }

    let effective = resolve_list_options(RawListOptions {
        probe: opts.probe,
        include_bastions: opts.include_bastions,
        no_bastion_discovery: opts.no_bastion_discovery,
        show_all: opts.show_all,
        for_mcp: false,
    });
    prepare_outbound_gate_for_list(effective.probe, effective.include_bastions)?;
    let items = collect_list_items(records, &effective)?;

    if opts.json {
        print_json(&items)?;
    } else if items.is_empty() {
        println!("(no records)");
    } else {
        print_table(&items);
    }
    Ok(())
}

fn print_json(items: &[BastionListItem]) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(items)
            .map_err(|e| crate::utils::errors::BrokreError::Cli(e.to_string()))?
    );
    Ok(())
}

fn print_table(items: &[BastionListItem]) {
    let mut by_profile: std::collections::BTreeMap<String, Vec<&BastionListItem>> =
        Default::default();
    for item in items {
        by_profile
            .entry(item.profile.clone())
            .or_default()
            .push(item);
    }
    for (profile, recs) in by_profile {
        println!("== {} ==", profile);
        for r in recs {
            let host = r.host_alias.as_deref().unwrap_or("-");
            let last = r
                .last_used_at
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "never".into());
            let route = if r.route.is_empty() {
                "-".to_string()
            } else {
                r.route.join("::")
            };
            let access = r.access.as_deref().unwrap_or("-");
            let status = format_status_display(r);
            println!(
                "  {:<28}  kind={:<6} route={:<12} access={:<14} host={:<20} status={:<32} last_used={}",
                r.addr, format!("{:?}", r.kind).to_lowercase(), route, access, host, status, last
            );
        }
    }
}
