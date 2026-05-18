use crate::utils::errors::Result;
use crate::vault::store::VaultStore;

pub fn run(
    profile_filter: Option<String>,
    labels: Vec<String>,
    host_glob: Option<String>,
    name_glob: Option<String>,
    json: bool,
) -> Result<()> {
    let store = VaultStore::open()?;
    let mut records = store.list()?;

    if let Some(p) = profile_filter {
        records.retain(|r| r.profile == p);
    }
    if !labels.is_empty() {
        records.retain(|r| labels.iter().all(|l| r.labels.contains(l)));
    }
    if let Some(ref h) = host_glob {
        records.retain(|r| {
            r.host_alias
                .as_ref()
                .map(|a| a.contains(h))
                .unwrap_or(false)
        });
    }
    if let Some(ref n) = name_glob {
        records.retain(|r| r.name.contains(n));
    }

    if json {
        let out: Vec<_> = records
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "profile": r.profile,
                    "name": r.name,
                    "labels": r.labels,
                    "host_alias": r.host_alias,
                    "created_at": r.created_at,
                    "last_used_at": r.last_used_at,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else if records.is_empty() {
        println!("(no records)");
    } else {
        // Group by profile
        let mut by_profile: std::collections::BTreeMap<String, Vec<_>> = Default::default();
        for r in records {
            by_profile.entry(r.profile.clone()).or_default().push(r);
        }
        for (profile, recs) in by_profile {
            println!("== {} ==", profile);
            for r in recs {
                let host = r.host_alias.as_deref().unwrap_or("-");
                let last = r
                    .last_used_at
                    .map(|t| t.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "never".into());
                println!("  {:<24}  host={:<24}  last_used={}", r.name, host, last);
            }
        }
    }
    Ok(())
}
