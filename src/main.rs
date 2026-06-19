use brokre::cli;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// brokre — AI-safe credential broker.
///
/// Usage patterns:
///
///   brokre ssh root@host           # first time: type password; offered to save.
///   brokre ssh prod-bastion        # next time: alias auto-injects the password.
///   brokre ssh prod-bastion uptime # one-shot remote command via saved alias.
///   brokre list                    # show saved aliases (metadata only).
///   brokre rm ssh prod-bastion     # delete (requires passphrase or YES).
///   brokre reveal ssh prod-bastion # show plaintext (TTY + passphrase required).
///   brokre audit list                # query audit history (metadata only).
///   brokre audit verify                # verify the tamper-evident audit log.
#[derive(Parser)]
#[command(name = "brokre", version, about, long_about = None)]
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
    /// pass-through that's the whole point of brokre.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Subcommand)]
enum AuditCmd {
    /// List audit events (metadata only — args are redacted).
    List {
        #[arg(short, long)]
        profile: Option<String>,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        action: Option<String>,
        #[arg(short, long)]
        source: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(short, long, default_value_t = 50)]
        limit: usize,
        #[arg(short, long, default_value_t = 0)]
        offset: usize,
        #[arg(long)]
        json: bool,
    },
    /// Verify the tamper-evident audit log chain.
    Verify {
        #[arg(long)]
        json: bool,
    },
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
        brokre::cli::injector::run_internal_injector_main();
    }

    #[cfg(unix)]
    if std::env::var_os("BROKRE_INTERNAL_ASKPASS").is_some() {
        brokre::cli::injector::run_internal_askpass_main();
    }

    #[cfg(unix)]
    {
        let mode = if cfg!(debug_assertions) {
            brokre::security::hardening::HardeningMode::WarnOnly
        } else {
            brokre::security::hardening::HardeningMode::Enforce
        };
        let _ = brokre::security::hardening::apply_hardening_cached(mode);
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
            AuditCmd::List {
                profile,
                name,
                action,
                source,
                since,
                until,
                limit,
                offset,
                json,
            } => cli::audit::run_list(cli::audit::ListOptions {
                profile,
                name,
                action,
                source,
                since,
                until,
                limit,
                offset,
                json,
            }),
            AuditCmd::Verify { json } => cli::audit::run_verify(json),
        },
        Some(Commands::Manage { onboard, open }) => cli::manage::run(onboard, open),
        Some(Commands::Mcp) => cli::mcp::run(),
        Some(Commands::External(raw)) => {
            // raw[0] is the binary name (e.g. "ssh"), raw[1..] are args.
            let mut it = raw.into_iter();
            let binary = match it.next() {
                Some(b) => b.to_string_lossy().into_owned(),
                None => {
                    eprintln!("brokre: empty external command");
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
        eprintln!("brokre: {}", e);
        std::process::exit(1);
    }
}

fn maybe_spawn_onboard(command: &Option<Commands>) {
    if matches!(command, Some(Commands::Manage { .. })) {
        return;
    }
    if brokre::manage::onboard::is_onboard_complete() {
        return;
    }
    if brokre::manage::onboard::was_onboard_spawned() {
        return;
    }
    if !brokre::security::tty::stdin_is_real_tty() {
        return;
    }
    if brokre::manage::onboard::mark_onboard_spawned().is_err() {
        return;
    }
    cli::manage::spawn_onboard_background();
}

fn print_usage() {
    eprintln!(
        "brokre {} — AI-safe credential broker",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  brokre <cli> [args...]              run any CLI through brokre");
    eprintln!("  brokre list [--profile P] [--json]  list saved aliases");
    eprintln!("  brokre rm <profile> <alias>         delete an alias");
    eprintln!("  brokre reveal <profile> <alias>     show stored plaintext (TTY + passphrase)");
    eprintln!("  brokre audit list [--profile P] [--json]  query audit history");
    eprintln!("  brokre audit verify [--json]            verify tamper-evident log");
    eprintln!("  brokre manage [--onboard] [--open]    local credential manager (web UI)");
    eprintln!("  brokre mcp                          MCP server for Cursor / Claude Code");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  brokre ssh root@10.0.0.1            first-time, type password, then save");
    eprintln!("  brokre ssh prod                     reuse saved alias");
    eprintln!("  brokre ssh prod uname -a            one-shot remote command via alias");
    eprintln!("  brokre mysql prod-db -e \"SHOW TABLES\"  one-shot SQL via alias");
    eprintln!("  brokre mysql -h db -u root          first-time mysql login");
}
