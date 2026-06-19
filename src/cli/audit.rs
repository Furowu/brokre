use crate::audit::query::{list, verify_with_stats, AuditQuery, VerifyStats};
use crate::utils::errors::Result;
use crate::utils::paths::audit_path;
use crate::vault::keychain::get_or_init_audit_hmac_key;

pub struct ListOptions {
    pub profile: Option<String>,
    pub name: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub json: bool,
}

pub fn run_list(opts: ListOptions) -> Result<()> {
    let query = AuditQuery {
        profile: opts.profile,
        name: opts.name,
        action: opts.action,
        source: opts.source,
        since: opts.since,
        until: opts.until,
        limit: opts.limit,
        offset: opts.offset,
        newest_first: true,
    };
    let result = list(query)?;

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return Ok(());
    }

    if result.events.is_empty() {
        println!("No audit events matched.");
        return Ok(());
    }

    println!(
        "Matched {} event(s), showing {} (offset {}).",
        result.total_matched,
        result.events.len(),
        opts.offset
    );
    println!(
        "{:<24} {:<16} {:<8} {:<16} {:<6} {:<6} {}",
        "TIME", "ACTION", "SOURCE", "PROFILE/NAME", "EXIT", "MS", "COMMAND"
    );
    for ev in &result.events {
        let profile_name = format!("{}/{}", ev.profile, ev.name);
        let exit = ev.exit.map(|c| c.to_string()).unwrap_or_else(|| "-".into());
        let dur = ev
            .dur_ms
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".into());
        let source = ev.source.as_deref().unwrap_or("-");
        let cmd = if ev.args_redacted.is_empty() {
            "-".to_string()
        } else {
            ev.args_redacted.join(" ")
        };
        println!(
            "{:<24} {:<16} {:<8} {:<16} {:<6} {:<6} {}",
            ev.ts, ev.action, source, profile_name, exit, dur, cmd
        );
    }
    Ok(())
}

pub fn run_verify(json: bool) -> Result<()> {
    let path = audit_path();
    let key = get_or_init_audit_hmac_key()?;
    let stats = verify_with_stats(&path, &key)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&stats).unwrap());
    } else {
        print_verify_human(&stats);
    }
    Ok(())
}

fn print_verify_human(stats: &VerifyStats) {
    println!("Audit chain verified successfully.");
    println!("Events: {}", stats.count);
    if let Some(ref first) = stats.first_ts {
        println!("First:  {}", first);
    }
    if let Some(ref last) = stats.last_ts {
        println!("Last:   {}", last);
    }
}
