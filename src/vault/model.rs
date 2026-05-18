use crate::vault::crypto::record::RecordCiphertext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single saved credential. The PTY-pass-through architecture means we
/// no longer track per-field metadata or injection strategy — every record
/// just carries the secret payload and enough context to recall it later.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: Uuid,
    pub profile: String,
    pub name: String,
    pub labels: Vec<String>,
    pub host_alias: Option<String>,
    /// Compatibility: old records may have this as Option.
    pub binary: Option<String>,
    /// Compatibility: old records may have this as Option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields_meta: Option<Vec<FieldMeta>>,
    /// Original arg list the user invoked.
    #[serde(default)]
    pub saved_args: Vec<String>,
    pub crypto: RecordCiphertext,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub schema_version: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldMeta {
    pub name: String,
    pub secret: bool,
    pub hint: Option<String>,
}

impl SecretRecord {
    pub fn validate_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || c == '_'
                    || c == '.'
                    || c == '/'
                    || c == '-'
                    || c == '@'
            })
    }
}
