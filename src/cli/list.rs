use crate::bastion::discover::{build_local_items, discover_remote_items, merge_list_items, DiscoverOptions};
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

    let mut items = build_local_items(records, opts.probe)?;

    let include_bastions = opts.include_bastions || (opts.probe && !opts.no_bastion_discovery);
    if include_bastions && !opts.no_bastion_discovery {
        let remote = discover_remote_items(&DiscoverOptions {
            probe: opts.probe,
            include_bastions: true,
        })?;
        items = merge_list_items(items, remote);
    }

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
        serde_json::to_string_pretty(items).map_err(|e| crate::utils::errors::BrokreError::Cli(e.to_string()))?
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
            let status = r
                .status
                .as_ref()
                .map(|s| {
                    if s.reachable {
                        format!("up@{} {}ms", s.source, s.probe_ms.unwrap_or(0))
                    } else {
                        format!(
                            "down@{} {}",
                            s.source,
                            s.error.as_deref().unwrap_or("?")
                        )
                    }
                })
                .unwrap_or_else(|| "-".into());
            println!(
                "  {:<28}  kind={:<6} route={:<12} host={:<20} status={:<16} last_used={}",
                r.addr, format!("{:?}", r.kind).to_lowercase(), route, host, status, last
            );
        }
    }
}
