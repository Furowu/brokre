//! Effective list options, reachability filtering, and access/availability enrichment.

use crate::bastion::discover::{
    build_local_items, discover_remote_items, merge_list_items, DiscoverOptions,
};
use crate::bastion::model::{Availability, BastionListItem};
use crate::utils::errors::Result;
use crate::vault::model::SecretRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveListOptions {
    pub probe: bool,
    pub include_bastions: bool,
    pub reachable_only: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RawListOptions {
    pub probe: bool,
    pub include_bastions: bool,
    pub no_bastion_discovery: bool,
    /// Explicit filter: only show reachable (and unknown) aliases.
    pub reachable_only: bool,
    /// CLI `--all` or MCP `all=true` — forces reachable_only off (compat).
    pub show_all: bool,
    pub for_mcp: bool,
}

pub fn resolve_list_options(raw: RawListOptions) -> EffectiveListOptions {
    let include_bastions = raw.include_bastions && !raw.no_bastion_discovery;
    let probe = raw.probe;
    let reachable_only = raw.reachable_only && !raw.show_all;

    EffectiveListOptions {
        probe,
        include_bastions,
        reachable_only,
    }
}

pub fn enrich_list_items(items: &mut [BastionListItem]) {
    for item in items.iter_mut() {
        item.availability = item.status.as_ref().map(|s| {
            if s.reachable {
                Availability::Available
            } else {
                Availability::Unavailable
            }
        });
        item.access = Some(compute_access(item));
    }
}

fn compute_access(item: &BastionListItem) -> String {
    if item.route.is_empty() {
        "direct".into()
    } else {
        format!("via_{}", item.route.join("_"))
    }
}

pub fn filter_list_items(
    items: Vec<BastionListItem>,
    reachable_only: bool,
) -> Vec<BastionListItem> {
    if !reachable_only {
        return items;
    }
    items
        .into_iter()
        .filter(|item| match item.status.as_ref() {
            Some(s) => s.reachable,
            None => true,
        })
        .collect()
}

pub fn format_status_display(item: &BastionListItem) -> String {
    match (&item.availability, &item.status) {
        (Some(Availability::Available), Some(s)) => {
            format!("available ({}, {}ms)", s.source, s.probe_ms.unwrap_or(0))
        }
        (Some(Availability::Unavailable), Some(s)) => format!(
            "unavailable ({}, {})",
            s.source,
            s.error.as_deref().unwrap_or("?")
        ),
        _ => "unknown".into(),
    }
}

/// Build the full list pipeline: local vault → optional bastion discovery → enrich → filter.
pub fn collect_list_items(
    records: Vec<SecretRecord>,
    effective: &EffectiveListOptions,
) -> Result<Vec<BastionListItem>> {
    let mut items = build_local_items(records, effective.probe)?;
    if effective.include_bastions {
        let remote = discover_remote_items(&DiscoverOptions {
            probe: effective.probe,
            include_bastions: true,
        })?;
        items = merge_list_items(items, remote);
    }
    enrich_list_items(&mut items);
    Ok(filter_list_items(items, effective.reachable_only))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bastion::model::{ListItemKind, ProbeStatus};
    use crate::utils::test_home::with_temp_brokre_home;
    use serial_test::serial;

    fn sample_item(name: &str, reachable: Option<bool>) -> BastionListItem {
        BastionListItem {
            profile: "ssh".into(),
            name: name.into(),
            addr: name.into(),
            route: vec![],
            kind: ListItemKind::Local,
            host_alias: Some("10.0.0.1".into()),
            labels: vec![],
            created_at: None,
            last_used_at: None,
            status: reachable.map(|r| ProbeStatus {
                reachable: r,
                probe_ms: Some(1),
                checked_at: "2026-01-01T00:00:00Z".into(),
                error: if r { None } else { Some("refused".into()) },
                source: "local".into(),
            }),
            access: None,
            availability: None,
        }
    }

    #[test]
    #[serial]
    fn resolve_does_not_auto_enable_when_bastions_registered() {
        with_temp_brokre_home(|| {
            use crate::security::secret::SecretString;
            use crate::vault::service::auto_save;
            use crate::vault::store::VaultStore;
            let store = VaultStore::open().unwrap();
            auto_save(
                &store,
                "ssh",
                &["u@10.0.0.150".into()],
                SecretString::new("pw".into()),
                "b150",
            )
            .unwrap();
            crate::bastion::enable_bastion("b150").unwrap();

            let eff = resolve_list_options(RawListOptions {
                probe: false,
                include_bastions: false,
                no_bastion_discovery: false,
                reachable_only: false,
                show_all: false,
                for_mcp: false,
            });
            assert!(!eff.include_bastions);
            assert!(!eff.probe);
            assert!(!eff.reachable_only);
        });
    }

    #[test]
    fn resolve_explicit_include_bastions_only_when_requested() {
        let eff = resolve_list_options(RawListOptions {
            probe: false,
            include_bastions: true,
            no_bastion_discovery: false,
            reachable_only: false,
            show_all: false,
            for_mcp: true,
        });
        assert!(eff.include_bastions);
        assert!(!eff.probe);
        assert!(!eff.reachable_only);

        let disabled = resolve_list_options(RawListOptions {
            probe: false,
            include_bastions: true,
            no_bastion_discovery: true,
            reachable_only: false,
            show_all: false,
            for_mcp: true,
        });
        assert!(!disabled.include_bastions);
    }

    #[test]
    #[serial]
    fn resolve_no_bastions_fast_local() {
        with_temp_brokre_home(|| {
            let eff = resolve_list_options(RawListOptions {
                probe: false,
                include_bastions: false,
                no_bastion_discovery: false,
                reachable_only: false,
                show_all: false,
                for_mcp: false,
            });
            assert!(!eff.include_bastions);
            assert!(!eff.probe);
            assert!(!eff.reachable_only);
        });
    }

    #[test]
    fn resolve_default_probe_does_not_imply_reachable_only() {
        let eff = resolve_list_options(RawListOptions {
            probe: true,
            include_bastions: false,
            no_bastion_discovery: false,
            reachable_only: false,
            show_all: false,
            for_mcp: false,
        });
        assert!(eff.probe);
        assert!(!eff.reachable_only);
    }

    #[test]
    fn resolve_reachable_only_cleared_by_show_all() {
        let eff = resolve_list_options(RawListOptions {
            probe: true,
            include_bastions: false,
            no_bastion_discovery: false,
            reachable_only: true,
            show_all: true,
            for_mcp: false,
        });
        assert!(!eff.reachable_only);
    }

    #[test]
    fn filter_drops_unreachable_keeps_unknown() {
        let items = vec![
            sample_item("up", Some(true)),
            sample_item("down", Some(false)),
            BastionListItem {
                status: None,
                host_alias: None,
                ..sample_item("meta", None)
            },
        ];
        let out = filter_list_items(items, true);
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|i| i.name == "up"));
        assert!(out.iter().any(|i| i.name == "meta"));
    }

    #[test]
    fn access_direct_vs_routed() {
        let mut direct = sample_item("db", Some(true));
        enrich_list_items(std::slice::from_mut(&mut direct));
        assert_eq!(direct.access.as_deref(), Some("direct"));

        let mut routed = sample_item("db", Some(true));
        routed.route = vec!["b150".into()];
        routed.addr = "b150::db".into();
        routed.kind = ListItemKind::Inner;
        enrich_list_items(std::slice::from_mut(&mut routed));
        assert_eq!(routed.access.as_deref(), Some("via_b150"));
    }
}
