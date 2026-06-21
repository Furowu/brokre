pub mod discover;
pub mod list_policy;
pub mod gate;
pub mod key;
pub mod mcp_gate;
pub mod model;
pub mod probe;
pub mod registry;
pub mod route;
pub mod session;
pub mod transport;

pub use model::{BastionListItem, ListItemKind, ProbeStatus};
pub use registry::{disable_bastion, enable_bastion, is_registered_bastion, list_bastions};
pub use route::{build_routed_local_argv, parse_route, BastionRoute};
pub use gate::{
    ensure_outbound_unlocked, exec_touches_bastion_outbound, invocation_from_mcp,
    list_touches_bastion_outbound, unlock_via_tty_prompt,
};
pub use session::{gate_required, is_unlocked, unlock_session};
