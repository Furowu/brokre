use brokr::cli;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// brokr — AI-safe credential broker.
///
/// Usage patterns:
///
///   brokr ssh root@host           # first time: type password; offered to save.
///   brokr ssh prod-bastion        # next time: alias auto-injects the password.
///   brokr ssh prod-bastion uptime # one-shot remote command via saved alias.
///   brokr list                    # show saved aliases (metadata only).
///   brokr rm ssh prod-bastion     # delete (requires passphrase or YES).
///   brokr reveal ssh prod-bastion # show plaintext (TTY + passphrase required).
///   brokr audit verify            # verify the tamper-evident audit log.
#[derive(Parser)]
#[command(name = "brokr", version, about, long_about = None)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List saved credentials (metadata only — no secrets, no field lengths).
    List {
        #[arg(short, long)]
        profile: Option<String>,
        #[arg(short, long)]
        label: Vec<String>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        name_glob: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Remove a saved credential.
    Rm { profile: String, name: String },
    /// Reveal a saved credential's plaintext (TTY + passphrase required).
    Reveal {
        profile: String,
        name: String,
        #[arg(long)]
        field: Option<String>,
    },
    /// Audit log operations.
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
    },
    /// Local web UI for credential management (metadata read, password write-only).
    Manage {
        /// First-run onboarding banner.
        #[arg(long)]
        onboard: bool,
        /// Open the default browser to the manage URL.
        #[arg(long)]
        open: bool,
    },
    /// Model Context Protocol server for AI assistants (Cursor, Claude Code, …).
    Mcp,
    /// Any other word is treated as `<cli> [args...]` — the transparent
    /// pass-through that's the whole point of brokr.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Subcommand)]
enum AuditCmd {
    Verify,
}

fn main() {
    let _ = tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(Level::WARN)
            .with_writer(std::io::stderr)
            .finish(),
    );

    #[cfg(unix)]
    if std::env::args().nth(1).as_deref() == Some("--internal-injector") {
        brokr::cli::injector::run_internal_injector_main();
    }

    #[cfg(unix)]
    {
        let mode = if cfg!(debug_assertions) {
            brokr::security::hardening::HardeningMode::WarnOnly
        } else {
            brokr::security::hardening::HardeningMode::Enforce
        };
        let _ = brokr::security::hardening::apply_hardening_cached(mode);
    }

    let cli = Cli::parse();

    maybe_spawn_onboard(&cli.command);

    let res = match cli.command {
        Some(Commands::List {
            profile,
            label,
            host,
            name_glob,
            json,
        }) => cli::list::run(profile, label, host, name_glob, json),
        Some(Commands::Rm { profile, name }) => cli::rm::run(profile, name),
        Some(Commands::Reveal {
            profile,
            name,
            field,
        }) => cli::reveal::run(profile, name, field),
        Some(Commands::Audit { action }) => match action {
            AuditCmd::Verify => cli::audit::run_verify(),
        },
        Some(Commands::Manage { onboard, open }) => cli::manage::run(onboard, open),
        Some(Commands::Mcp) => cli::mcp::run(),
        Some(Commands::External(raw)) => {
            // raw[0] is the binary name (e.g. "ssh"), raw[1..] are args.
            let mut it = raw.into_iter();
            let binary = match it.next() {
                Some(b) => b.to_string_lossy().into_owned(),
                None => {
                    eprintln!("brokr: empty external command");
                    std::process::exit(2);
                }
            };
            let args: Vec<String> = it.map(|s| s.to_string_lossy().into_owned()).collect();
            cli::exec::run(binary, args)
        }
        None => {
            // No subcommand — print usage.
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = res {
        eprintln!("brokr: {}", e);
        std::process::exit(1);
    }
}

fn maybe_spawn_onboard(command: &Option<Commands>) {
    if matches!(command, Some(Commands::Manage { .. })) {
        return;
    }
    if brokr::manage::onboard::is_onboard_complete() {
        return;
    }
    if brokr::manage::onboard::was_onboard_spawned() {
        return;
    }
    if !brokr::security::tty::stdin_is_real_tty() {
        return;
    }
    if brokr::manage::onboard::mark_onboard_spawned().is_err() {
        return;
    }
    cli::manage::spawn_onboard_background();
}

fn print_usage() {
    eprintln!(
        "brokr {} — AI-safe credential broker",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  brokr <cli> [args...]              run any CLI through brokr");
    eprintln!("  brokr list [--profile P] [--json]  list saved aliases");
    eprintln!("  brokr rm <profile> <alias>         delete an alias");
    eprintln!("  brokr reveal <profile> <alias>     show stored plaintext (TTY + passphrase)");
    eprintln!("  brokr audit verify                 verify tamper-evident log");
    eprintln!("  brokr manage [--onboard] [--open]    local credential manager (web UI)");
    eprintln!("  brokr mcp                          MCP server for Cursor / Claude Code");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  brokr ssh root@10.0.0.1            first-time, type password, then save");
    eprintln!("  brokr ssh prod                     reuse saved alias");
    eprintln!("  brokr ssh prod uname -a            one-shot remote command via alias");
    eprintln!("  brokr mysql prod-db -e \"SHOW TABLES\"  one-shot SQL via alias");
    eprintln!("  brokr mysql -h db -u root          first-time mysql login");
}
