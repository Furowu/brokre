use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListItemKind {
    Local,
    Bastion,
    Inner,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeStatus {
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_ms: Option<u64>,
    pub checked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Where the probe ran: `local` or a bastion alias name.
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BastionListItem {
    pub profile: String,
    pub name: String,
    /// Addressable id (`name` for local, `bastion::inner` for routed).
    pub addr: String,
    pub route: Vec<String>,
    pub kind: ListItemKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProbeStatus>,
}

impl BastionListItem {
    pub fn from_local_record(rec: &crate::vault::model::SecretRecord) -> Self {
        Self {
            profile: rec.profile.clone(),
            name: rec.name.clone(),
            addr: rec.name.clone(),
            route: vec![],
            kind: if crate::bastion::registry::is_bastion_alias(&rec.name) {
                ListItemKind::Bastion
            } else {
                ListItemKind::Local
            },
            host_alias: rec.host_alias.clone(),
            labels: rec.labels.clone(),
            created_at: Some(rec.created_at),
            last_used_at: rec.last_used_at,
            status: None,
        }
    }

    pub fn with_inner_route(mut self, bastion: &str) -> Self {
        self.route = vec![bastion.to_string()];
        self.addr = format!("{}::{}", bastion, self.name);
        self.kind = ListItemKind::Inner;
        self
    }
}
