use crate::utils::paths::brokre_home;
use crate::vault::service::default_port_for;
use crate::vault::store::VaultStore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// How the manage form treats the user / login name field.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserFieldMode {
    /// No `-u` / `user@` in saved args (FTP, Redis, …).
    Hidden,
    /// Must be filled — empty makes the CLI fall back to the OS user and auth usually fails.
    Required,
    /// Custom / unknown CLI — optional.
    Optional,
}

/// A manage UI group maps to one tab/section (e.g. SSH, FTP, or user-defined GaussDB).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileGroupInfo {
    /// Section id (stable key for UI).
    pub id: String,
    /// Human label, e.g. "SSH", "GaussDB".
    pub label: String,
    /// Whether any binary in this group is on PATH.
    pub available: bool,
    /// Binary name used when creating a new credential in this section.
    pub create_profile: String,
    /// Binaries detected on PATH (for display).
    pub detected: Vec<String>,
    /// Vault `profile` values shown in this section.
    pub profiles: Vec<String>,
    /// User-defined or auto-discovered (not built-in preset).
    #[serde(default)]
    pub generic: bool,
    /// Manage form: whether user/login name is shown and required.
    pub user_field: UserFieldMode,
    /// Placeholder hint (e.g. `root` for SSH); not a default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_placeholder: Option<String>,
    /// Manage form: inline host+port row.
    pub port_field: PortFieldMode,
    /// Well-known default port for placeholder (omit from saved args when blank).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_port: Option<u16>,
}

/// How the manage form treats the port field beside host.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortFieldMode {
    /// Host only (MinIO `mc`, custom group before CLI name, …).
    Hidden,
    /// Known CLI default port (SSH 22, MySQL 3306, …).
    Optional,
    /// Unknown CLI — passed as `-p` before host.
    Generic,
}

pub fn port_field_mode(profile: &str) -> PortFieldMode {
    let bin = profile.rsplit('/').next().unwrap_or(profile);
    if bin.is_empty() {
        return PortFieldMode::Hidden;
    }
    if default_port_for(bin).is_some() {
        PortFieldMode::Optional
    } else if matches!(bin, "mc" | "minio") {
        PortFieldMode::Hidden
    } else {
        PortFieldMode::Generic
    }
}

pub fn user_field_mode(profile: &str) -> UserFieldMode {
    match profile.rsplit('/').next().unwrap_or(profile) {
        "ssh" | "scp" | "sftp" | "mysql" | "mariadb" | "postgres" | "psql" => {
            UserFieldMode::Required
        }
        "ftp" | "lftp" | "redis" | "redis-cli" | "clickhouse" | "clickhouse-client" | "mc"
        | "minio" => UserFieldMode::Hidden,
        _ => UserFieldMode::Optional,
    }
}

pub fn user_placeholder(profile: &str) -> Option<&'static str> {
    match profile.rsplit('/').next().unwrap_or(profile) {
        "ssh" | "scp" | "sftp" | "mysql" | "mariadb" => Some("root"),
        "postgres" | "psql" => Some("postgres"),
        _ => None,
    }
}

/// Validate manage create form user field against CLI semantics.
pub fn validate_user_for_profile(profile: &str, user: Option<&str>) -> Result<(), &'static str> {
    if user_field_mode(profile) == UserFieldMode::Required
        && user.map(str::trim).filter(|s| !s.is_empty()).is_none()
    {
        return Err("user is required for this CLI");
    }
    Ok(())
}

fn with_form_meta(create_profile: &str, mut info: ProfileGroupInfo) -> ProfileGroupInfo {
    info.user_field = user_field_mode(create_profile);
    info.user_placeholder = user_placeholder(create_profile).map(str::to_string);
    info.port_field = port_field_mode(create_profile);
    info.default_port = default_port_for(create_profile);
    info
}

struct ProfileGroupDef {
    id: &'static str,
    label: &'static str,
    detect_binaries: &'static [&'static str],
    vault_profiles: &'static [&'static str],
}

const BUILTIN_GROUPS: &[ProfileGroupDef] = &[
    ProfileGroupDef {
        id: "ssh",
        label: "SSH",
        detect_binaries: &["ssh"],
        vault_profiles: &["ssh", "scp", "sftp"],
    },
    ProfileGroupDef {
        id: "ftp",
        label: "FTP",
        detect_binaries: &["ftp"],
        vault_profiles: &["ftp"],
    },
    ProfileGroupDef {
        id: "lftp",
        label: "LFTP",
        detect_binaries: &["lftp"],
        vault_profiles: &["lftp"],
    },
    ProfileGroupDef {
        id: "mysql",
        label: "MySQL",
        detect_binaries: &["mysql", "mariadb"],
        vault_profiles: &["mysql", "mariadb"],
    },
    ProfileGroupDef {
        id: "postgres",
        label: "PostgreSQL",
        detect_binaries: &["psql"],
        vault_profiles: &["psql", "postgres"],
    },
    ProfileGroupDef {
        id: "redis",
        label: "Redis",
        detect_binaries: &["redis-cli"],
        vault_profiles: &["redis-cli", "redis"],
    },
    ProfileGroupDef {
        id: "clickhouse",
        label: "ClickHouse",
        detect_binaries: &["clickhouse-client"],
        vault_profiles: &["clickhouse-client", "clickhouse"],
    },
    ProfileGroupDef {
        id: "minio",
        label: "MinIO",
        detect_binaries: &["mc"],
        vault_profiles: &["mc", "minio"],
    },
];

#[derive(Debug, Deserialize)]
struct ManageToml {
    #[serde(default)]
    group: Vec<UserGroupToml>,
}

#[derive(Debug, Deserialize)]
struct UserGroupToml {
    id: String,
    label: String,
    binaries: Vec<String>,
}

fn binary_on_path(name: &str) -> bool {
    which::which(name).is_ok()
}

fn valid_cli_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains('/')
        && !name.contains('\\')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

fn pick_create_profile(binaries: &[String]) -> Option<String> {
    binaries.iter().find(|b| binary_on_path(b)).cloned()
}

fn group_from_def(def: &ProfileGroupDef) -> ProfileGroupInfo {
    let detected: Vec<String> = def
        .detect_binaries
        .iter()
        .filter(|b| binary_on_path(b))
        .map(|s| (*s).to_string())
        .collect();
    let available = !detected.is_empty();
    let create_profile = detected
        .first()
        .cloned()
        .unwrap_or_else(|| def.detect_binaries[0].to_string());
    let create_profile_for_meta = create_profile.clone();
    with_form_meta(
        &create_profile_for_meta,
        ProfileGroupInfo {
            id: def.id.to_string(),
            label: def.label.to_string(),
            available,
            create_profile,
            detected,
            profiles: def.vault_profiles.iter().map(|s| (*s).to_string()).collect(),
            generic: false,
            user_field: UserFieldMode::Optional,
            user_placeholder: None,
            port_field: PortFieldMode::Hidden,
            default_port: None,
        },
    )
}

fn load_user_groups() -> Vec<ProfileGroupInfo> {
    let path = brokre_home().join("manage.toml");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(cfg) = toml::from_str::<ManageToml>(&content) else {
        return Vec::new();
    };
    cfg.group
        .into_iter()
        .filter(|g| !g.id.is_empty() && !g.binaries.is_empty())
        .map(|g| {
            let detected: Vec<String> = g
                .binaries
                .iter()
                .filter(|b| binary_on_path(b))
                .cloned()
                .collect();
            let available = !detected.is_empty();
            let create_profile = pick_create_profile(&g.binaries)
                .unwrap_or_else(|| g.binaries[0].clone());
            let create_profile_for_meta = create_profile.clone();
            with_form_meta(
                &create_profile_for_meta,
                ProfileGroupInfo {
                    id: g.id,
                    label: g.label,
                    available,
                    create_profile,
                    detected,
                    profiles: g.binaries,
                    generic: true,
                    user_field: UserFieldMode::Optional,
                    user_placeholder: None,
                    port_field: PortFieldMode::Hidden,
                    default_port: None,
                },
            )
        })
        .collect()
}

fn orphan_vault_profiles(covered: &HashSet<String>) -> Vec<String> {
    let Ok(store) = VaultStore::open() else {
        return Vec::new();
    };
    let Ok(records) = store.list() else {
        return Vec::new();
    };
    let mut out: Vec<String> = records
        .into_iter()
        .map(|r| r.profile)
        .filter(|p| !covered.contains(p))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn synthesize_group(profile: &str) -> ProfileGroupInfo {
    let detected = if binary_on_path(profile) {
        vec![profile.to_string()]
    } else {
        vec![]
    };
    with_form_meta(
        profile,
        ProfileGroupInfo {
            id: format!("cli-{}", profile),
            label: profile.to_string(),
            available: !detected.is_empty(),
            create_profile: profile.to_string(),
            detected,
            profiles: vec![profile.to_string()],
            generic: true,
            user_field: UserFieldMode::Optional,
            user_placeholder: None,
            port_field: PortFieldMode::Hidden,
            default_port: None,
        },
    )
}

fn custom_cli_group() -> ProfileGroupInfo {
    ProfileGroupInfo {
        id: "custom".into(),
        label: "Other CLI".into(),
        available: true,
        create_profile: String::new(),
        detected: vec![],
        profiles: vec![],
        generic: true,
        user_field: UserFieldMode::Optional,
        user_placeholder: None,
        port_field: PortFieldMode::Hidden,
        default_port: None,
    }
}

/// Built-in + `~/.brokre/manage.toml` + vault orphans + catch-all custom section.
pub fn detect_profile_groups() -> Vec<ProfileGroupInfo> {
    let mut groups: Vec<ProfileGroupInfo> =
        BUILTIN_GROUPS.iter().map(group_from_def).collect();

    let mut by_id: HashMap<String, usize> = HashMap::new();
    for (i, g) in groups.iter().enumerate() {
        by_id.insert(g.id.clone(), i);
    }

    for ug in load_user_groups() {
        if let Some(&idx) = by_id.get(&ug.id) {
            groups[idx] = ug;
        } else {
            by_id.insert(ug.id.clone(), groups.len());
            groups.push(ug);
        }
    }

    let mut covered: HashSet<String> = HashSet::new();
    for g in &groups {
        for p in &g.profiles {
            covered.insert(p.clone());
        }
    }

    for profile in orphan_vault_profiles(&covered) {
        if by_id.contains_key(&format!("cli-{}", profile)) {
            continue;
        }
        let g = synthesize_group(&profile);
        by_id.insert(g.id.clone(), groups.len());
        covered.extend(g.profiles.iter().cloned());
        groups.push(g);
    }

    if !by_id.contains_key("custom") {
        groups.push(custom_cli_group());
    }

    groups
}

/// Any CLI binary on PATH may be registered (built-in, `manage.toml`, or ad-hoc).
pub fn profile_available_for_create(profile: &str) -> bool {
    if !valid_cli_profile_name(profile) {
        return false;
    }
    binary_on_path(profile)
}

/// Map vault profile to manage section id.
pub fn section_id_for_profile(profile: &str) -> Option<String> {
    detect_profile_groups()
        .into_iter()
        .find(|g| g.profiles.iter().any(|p| p == profile))
        .map(|g| g.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_field_mode_ssh_required() {
        assert_eq!(user_field_mode("ssh"), UserFieldMode::Required);
        assert_eq!(user_field_mode("mysql"), UserFieldMode::Required);
        assert_eq!(user_field_mode("redis-cli"), UserFieldMode::Hidden);
        assert_eq!(user_field_mode("gsql"), UserFieldMode::Optional);
    }

    #[test]
    fn validate_user_rejects_empty_ssh() {
        assert!(validate_user_for_profile("ssh", None).is_err());
        assert!(validate_user_for_profile("ssh", Some("")).is_err());
        assert!(validate_user_for_profile("ssh", Some("root")).is_ok());
        assert!(validate_user_for_profile("ftp", None).is_ok());
    }

    #[test]
    fn ssh_group_exposes_user_metadata() {
        let groups = detect_profile_groups();
        let ssh = groups.iter().find(|g| g.id == "ssh").unwrap();
        assert_eq!(ssh.user_field, UserFieldMode::Required);
        assert_eq!(ssh.user_placeholder.as_deref(), Some("root"));
        assert_eq!(ssh.port_field, PortFieldMode::Optional);
        assert_eq!(ssh.default_port, Some(22));
    }

    #[test]
    fn minio_hides_port_field() {
        assert_eq!(port_field_mode("mc"), PortFieldMode::Hidden);
        let groups = detect_profile_groups();
        let minio = groups.iter().find(|g| g.id == "minio").unwrap();
        assert_eq!(minio.port_field, PortFieldMode::Hidden);
    }

    #[test]
    fn section_mapping_covers_openssh_family() {
        assert_eq!(section_id_for_profile("ssh").as_deref(), Some("ssh"));
        assert_eq!(section_id_for_profile("scp").as_deref(), Some("ssh"));
        assert_eq!(section_id_for_profile("sftp").as_deref(), Some("ssh"));
    }

    #[test]
    fn detect_returns_all_builtin_groups() {
        let groups = detect_profile_groups();
        assert!(groups.iter().any(|g| g.id == "ssh"));
        assert!(groups.iter().any(|g| g.id == "ftp"));
        assert!(groups.iter().any(|g| g.id == "custom"));
    }

    #[test]
    fn valid_cli_name_rejects_paths() {
        assert!(!valid_cli_profile_name("/usr/bin/ssh"));
        assert!(valid_cli_profile_name("gsql"));
    }

    #[test]
    fn profile_available_requires_path_binary() {
        assert!(!profile_available_for_create("definitely-not-a-real-brokre-cli-xyz"));
        if which::which("ssh").is_ok() {
            assert!(profile_available_for_create("ssh"));
        }
    }

    #[test]
    fn user_manage_toml_adds_group() {
        let tmp = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let brokre = tmp.path().join(".brokre");
        std::fs::create_dir_all(&brokre).unwrap();
        std::fs::write(
            brokre.join("manage.toml"),
            r#"
[[group]]
id = "gaussdb"
label = "GaussDB"
binaries = ["gsql", "gaussdb"]
"#,
        )
        .unwrap();

        let groups = detect_profile_groups();
        let gauss = groups.iter().find(|g| g.id == "gaussdb").expect("gaussdb group");
        assert!(gauss.generic);
        assert_eq!(gauss.label, "GaussDB");

        match old_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}
