use brokre::cli;
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(
    name = "brokre",
    version,
    about = "AI-safe credential broker CLI",
    long_about = "\
brokre wraps any CLI on your PATH and injects saved passwords at prompts.\n\
Passwords never appear in environment variables, AI context, or ps output.\n\
\n\
PASS-THROUGH (core usage — any CLI):\n\
  brokre <cli-binary> [args...]\n\
\n\
  brokre ssh root@10.0.0.1          # first time: type password; offered to save\n\
  brokre ssh prod-bastion           # saved alias: password auto-injected\n\
  brokre ssh prod-bastion uname -a  # one-shot remote command (split argv)\n\
  brokre mysql prod-db -e \"SHOW TABLES\"\n\
  brokre <your-cli> <alias> [args...]\n\
\n\
REMOTE SSH: argv after the alias are separate tokens, not one shell string.\n\
  brokre ssh prod docker ps         # good\n\
  brokre ssh prod sh -c 'script'    # good (script is one -c argument)\n\
  brokre ssh prod \"docker ps\"       # shell may work locally; prefer split argv\n\
\n\
BUILT-IN SUBCOMMANDS:\n\
  brokre list [--json] [--no-probe]  # list aliases (probes reachability by default)\n\
  brokre manage [--open]            # local web UI for credentials\n\
  brokre mcp                        # MCP server for AI assistants\n\
  brokre mcp setup                  # register brokre MCP in detected IDEs\n\
  brokre tunnel doctor <bastion>     # check SessionRelay agent over SSH stdio\n\
  brokre version [--check]          # show version; query GitHub for updates\n\
  brokre upgrade                    # upgrade CLI from GitHub Releases\n\
  brokre bastion enable <alias>     # bastion broker (see brokre bastion --help)\n\
  brokre reveal / rm / audit        # human-only or metadata (see --help)\n\
\n\
MCP (Cursor, Claude Code, …): use brokre_list / brokre_exec tools — see README.\n\
  brokre_exec binary=ssh, args=[\"prod\",\"uname\",\"-a\"]  ==  brokre ssh prod uname -a\n\
\n\
Run `brokre list --help`, `brokre bastion --help`, etc. for subcommand options."
)]
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
        /// Compat flag (probe is on by default). Prefer `--no-probe` to disable.
        #[arg(long, hide = true, action = clap::ArgAction::SetTrue)]
        probe: bool,
        /// Skip reachability probe (metadata only, fast).
        #[arg(long = "no-probe", action = clap::ArgAction::SetTrue)]
        no_probe: bool,
        /// Include aliases discovered on registered bastions.
        #[arg(long)]
        include_bastions: bool,
        /// Skip remote bastion discovery (used on bastion hosts).
        #[arg(long, hide = true)]
        no_bastion_discovery: bool,
        /// Only show reachable aliases (hides unavailable).
        #[arg(long = "reachable-only")]
        reachable_only: bool,
        /// Show all aliases including unreachable (disables --reachable-only).
        #[arg(long)]
        all: bool,
        #[arg(long, hide = true)]
        probe_timeout_ms: Option<u64>,
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
    Mcp {
        #[command(subcommand)]
        action: Option<McpCmd>,
    },
    /// Bastion proxy: promote SSH aliases as credential brokers.
    Bastion {
        #[command(subcommand)]
        action: BastionCmd,
    },
    /// SSH stdio SessionRelay tunnel operations.
    Tunnel {
        #[command(subcommand)]
        action: TunnelCmd,
    },
    /// Show brokre version and install location.
    Version {
        /// Query GitHub for the latest release.
        #[arg(long, short = 'c')]
        check: bool,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Download and install a brokre release from GitHub (install.sh parity).
    Upgrade {
        /// Install a specific version (e.g. 0.2.10) instead of latest.
        #[arg(value_name = "VERSION")]
        version: Option<String>,
        /// Reinstall even when already on the target version.
        #[arg(long)]
        force: bool,
        /// Only report whether an upgrade is available (exit 1 if yes).
        #[arg(long)]
        check: bool,
    },
    /// Any other word is treated as `<cli> [args...]` — the transparent
    /// pass-through that's the whole point of brokre.
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Subcommand)]
enum McpCmd {
    /// Register brokre in detected IDEs (same flow as `npm i brokre` postinstall).
    Setup {
        /// Preview changes without writing IDE config files.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite existing brokre MCP entries.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum BastionCmd {
    /// Promote a saved SSH alias as a bastion broker.
    Enable { alias: String },
    /// Remove a bastion registration.
    Disable { alias: String },
    /// List registered bastions.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Set the bastion unlock key (TTY required).
    SetKey,
    /// Unlock bastion outbound access for the current TTL session (TTY required).
    Unlock,
    /// Lock (clear) the bastion session immediately.
    Lock,
    /// Fetch and print aliases from a bastion (`brokre list --json --probe`).
    Sync {
        alias: String,
        #[arg(long)]
        json: bool,
    },
    /// Gate policy: default (bastion outbound only) or strict (all operations).
    Strict {
        /// `on`, `off`, or `status` (default).
        #[arg(value_name = "MODE")]
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
enum TunnelCmd {
    /// Run a tunnel agent on stdio (normally started through SSH).
    Agent {
        /// Use stdin/stdout for the tunnel protocol.
        #[arg(long)]
        stdio: bool,
        /// Print tunnel protocol version.
        #[arg(long)]
        version: bool,
    },
    /// Start the remote agent and verify protocol/arch.
    Up {
        bastion: String,
        #[arg(long)]
        json: bool,
    },
    /// Diagnose remote agent reachability and compatibility.
    Doctor {
        bastion: String,
        #[arg(long)]
        json: bool,
    },
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

    brokre::vault::keychain::prepare_platform_storage();

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
            probe: _probe,
            no_probe,
            include_bastions,
            no_bastion_discovery,
            reachable_only,
            all,
            probe_timeout_ms,
        }) => {
            if let Some(ms) = probe_timeout_ms {
                std::env::set_var("BROKRE_PROBE_TIMEOUT_MS", ms.to_string());
            }
            let probe = if no_probe { false } else { true };
            cli::list::run(cli::list::ListOptions {
                profile_filter: profile,
                labels: label,
                host_glob: host,
                name_glob,
                json,
                probe,
                include_bastions,
                no_bastion_discovery,
                reachable_only,
                show_all: all,
            })
        }
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
        Some(Commands::Bastion { action }) => match action {
            BastionCmd::Enable { alias } => cli::bastion::run_enable(alias),
            BastionCmd::Disable { alias } => cli::bastion::run_disable(alias),
            BastionCmd::List { json } => cli::bastion::run_list(json),
            BastionCmd::SetKey => cli::bastion::run_set_key(),
            BastionCmd::Unlock => cli::bastion::run_unlock(),
            BastionCmd::Lock => cli::bastion::run_lock(),
            BastionCmd::Sync { alias, json } => cli::bastion::run_sync(alias, json),
            BastionCmd::Strict { mode } => cli::bastion::run_strict(mode),
        },
        Some(Commands::Tunnel { action }) => match action {
            TunnelCmd::Agent { stdio, version } => cli::tunnel::run_agent(stdio, version),
            TunnelCmd::Up { bastion, json } => cli::tunnel::run_up(bastion, json),
            TunnelCmd::Doctor { bastion, json } => cli::tunnel::run_doctor(bastion, json),
        },
        Some(Commands::Mcp { action }) => match action {
            None => cli::mcp::run(),
            Some(McpCmd::Setup { dry_run, force }) => cli::mcp::run_setup(dry_run, force),
        },
        Some(Commands::Version { check, json }) => cli::upgrade::run_version(json, check),
        Some(Commands::Upgrade {
            version,
            force,
            check,
        }) => cli::upgrade::run_upgrade(version, force, check),
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
    eprintln!("  brokre list [--profile P] [--json] [--no-probe]  list aliases (probes by default)");
    eprintln!("  brokre bastion enable <ssh-alias>        register bastion broker");
    eprintln!("  brokre bastion unlock                    unlock bastion outbound session");
    eprintln!("  brokre tunnel doctor <bastion>      check SessionRelay tunnel agent");
    eprintln!("  brokre rm <profile> <alias>         delete an alias");
    eprintln!("  brokre reveal <profile> <alias>     show stored plaintext (TTY + passphrase)");
    eprintln!("  brokre audit list [--profile P] [--json]  query audit history");
    eprintln!("  brokre audit verify [--json]            verify tamper-evident log");
    eprintln!("  brokre manage [--onboard] [--open]    local credential manager (web UI)");
    eprintln!("  brokre mcp                          MCP server for Cursor / Claude Code");
    eprintln!("  brokre mcp setup [--dry-run]        register MCP in detected IDEs");
    eprintln!("  brokre version [--check] [--json]   show version / check for updates");
    eprintln!("  brokre upgrade [VERSION] [--force]  upgrade from GitHub Releases");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  brokre ssh root@10.0.0.1            first-time, type password, then save");
    eprintln!("  brokre ssh prod                     reuse saved alias");
    eprintln!("  brokre ssh prod uname -a            one-shot remote command via alias");
    eprintln!("  brokre mysql prod-db -e \"SHOW TABLES\"  one-shot SQL via alias");
    eprintln!("  brokre mysql -h db -u root          first-time mysql login");
}
