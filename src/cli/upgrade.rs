//! Version reporting and self-upgrade from GitHub Releases (install.sh parity).

use crate::utils::errors::{BrokreError, Result};
use crate::utils::paths::brokre_home;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REPO: &str = "Furowu/brokre";

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionReport {
    pub version: String,
    pub binary: PathBuf,
    pub target: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub install: String,
}

pub fn detect_target() -> Result<&'static str> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return Ok("aarch64-apple-darwin");
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return Ok("x86_64-apple-darwin");
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Ok("x86_64-unknown-linux-gnu");
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return Ok("aarch64-unknown-linux-gnu");
    #[cfg(target_os = "windows")]
    return Ok("x86_64-pc-windows-msvc");
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "windows",
    )))]
    Err(BrokreError::Runtime(format!(
        "unsupported platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )))
}

pub fn gather_version_report(check_latest: bool) -> Result<VersionReport> {
    let binary = std::env::current_exe()
        .map_err(BrokreError::Io)?
        .canonicalize()
        .map_err(BrokreError::Io)?;
    let target = detect_target()?.to_string();
    let version = current_version().to_string();
    let install = classify_install(&binary);

    let latest = if check_latest {
        Some(fetch_latest_version()?)
    } else {
        None
    };
    let update_available = latest
        .as_ref()
        .is_some_and(|l| version_newer_than(l, &version));

    Ok(VersionReport {
        version,
        binary,
        target,
        latest,
        update_available,
        install,
    })
}

pub fn run_version(json: bool, check_latest: bool) -> Result<()> {
    let report = gather_version_report(check_latest)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| { BrokreError::Runtime(format!("version json: {e}")) })?
        );
        return Ok(());
    }

    println!("brokre {}", report.version);
    println!("binary: {}", report.binary.display());
    println!("target: {}", report.target);
    println!("install: {}", report.install);
    if let Some(latest) = &report.latest {
        if report.update_available {
            println!("latest: {latest} (update available — run: brokre upgrade)");
        } else {
            println!("latest: {latest} (up to date)");
        }
    } else {
        println!("latest: (run brokre version --check to query GitHub)");
    }
    Ok(())
}

pub fn run_upgrade(version: Option<String>, force: bool, check_only: bool) -> Result<()> {
    let current = current_version().to_string();
    let target_ver = match version.as_deref() {
        None | Some("latest") => fetch_latest_version()?,
        Some(v) => normalize_version(v),
    };
    let target_triple = detect_target()?;

    if !force && !version_newer_than(&target_ver, &current) && target_ver == current {
        if check_only {
            println!("brokre v{current} (up to date)");
            return Ok(());
        }
        println!("brokre v{current} already installed (up to date).");
        println!("Force reinstall: brokre upgrade --force");
        return Ok(());
    }

    if check_only {
        if version_newer_than(&target_ver, &current) {
            println!("brokre v{current} → v{target_ver} available (run: brokre upgrade)");
            std::process::exit(1);
        }
        println!("brokre v{current} (up to date)");
        return Ok(());
    }

    if version_newer_than(&target_ver, &current) {
        eprintln!("Upgrading brokre v{current} → v{target_ver} for {target_triple}...");
    } else {
        eprintln!("Installing brokre v{target_ver} for {target_triple}...");
    }

    let dest = install_destination()?;
    let tmp_base = std::env::temp_dir().join(format!("brokre-upgrade.{}", std::process::id()));
    fs::create_dir_all(&tmp_base).map_err(BrokreError::Io)?;
    let tgz = tmp_base.join("brokre.tar.gz");
    let result = (|| {
        download_release_tarball(&target_ver, target_triple, &tgz)?;
        let extract_dir = tmp_base.join("extract");
        fs::create_dir_all(&extract_dir).map_err(BrokreError::Io)?;
        extract_tarball(&tgz, &extract_dir)?;
        let extracted = binary_name_in_dir(&extract_dir)?;
        install_binary_atomically(&extracted, &dest)?;
        write_version_stamp(&dest, &target_ver)?;
        Ok::<(), BrokreError>(())
    })();
    let _ = fs::remove_dir_all(&tmp_base);
    result?;

    println!("Installed brokre v{target_ver} to {}", dest.display());
    if dest
        != std::env::current_exe()
            .map_err(BrokreError::Io)?
            .canonicalize()
            .map_err(BrokreError::Io)?
    {
        eprintln!(
            "Note: active binary may still be an older copy on PATH until you open a new shell."
        );
        eprintln!("       Ensure ~/.brokre/bin is on PATH, or re-run: curl -fsSL https://raw.githubusercontent.com/{REPO}/main/install.sh | bash");
    }
    Ok(())
}

fn classify_install(binary: &Path) -> String {
    let path = binary.to_string_lossy();
    if path.contains("/node_modules/") || path.contains("\\node_modules\\") {
        return "npm".into();
    }
    if path.contains("/.brokre/bin") || path.contains("\\.brokre\\bin") {
        return "user (~/.brokre/bin)".into();
    }
    if path.starts_with("/usr/local/bin") || path.starts_with("/opt/homebrew/bin") {
        return "system".into();
    }
    if path.contains("/target/debug") || path.contains("/target/release") {
        return "development build".into();
    }
    "native".into()
}

fn normalize_version(v: &str) -> String {
    v.trim().trim_start_matches('v').to_string()
}

pub fn fetch_latest_version() -> Result<String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = curl_get(&url)?;
    parse_github_tag_name(&body)
        .ok_or_else(|| BrokreError::Runtime("failed to parse latest release from GitHub".into()))
}

fn parse_github_tag_name(json: &str) -> Option<String> {
    let marker = "\"tag_name\"";
    let start = json.find(marker)? + marker.len();
    let rest = json[start..].trim_start();
    let quote = rest.find('"')? + 1;
    let end = rest[quote..].find('"')? + quote;
    let tag = &rest[quote..end];
    Some(normalize_version(tag))
}

pub fn version_newer_than(candidate: &str, current: &str) -> bool {
    match (parse_semver(candidate), parse_semver(current)) {
        (Some(a), Some(b)) => a > b,
        _ => normalize_version(candidate) > normalize_version(current),
    }
}

fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let s = normalize_version(s);
    let mut parts = s.split('.');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn curl_get(url: &str) -> Result<String> {
    let output = Command::new("curl")
        .args(["-fsSL", url])
        .output()
        .map_err(|_| {
            BrokreError::Runtime("curl not found — install curl or use install.sh".into())
        })?;
    if !output.status.success() {
        return Err(BrokreError::Runtime(format!(
            "curl failed (HTTP) for {url}"
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn curl_download(url: &str, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let status = Command::new("curl")
        .args(["-fsSL", "-o", dest.to_string_lossy().as_ref(), url])
        .status()
        .map_err(|_| {
            BrokreError::Runtime("curl not found — install curl or use install.sh".into())
        })?;
    if !status.success() {
        return Err(BrokreError::Runtime(format!("download failed: {url}")));
    }
    Ok(())
}

fn download_release_tarball(version: &str, target: &str, dest: &Path) -> Result<()> {
    let url =
        format!("https://github.com/{REPO}/releases/download/v{version}/brokre-{target}.tar.gz");
    eprintln!("Downloading {url}...");
    curl_download(&url, dest)
}

fn extract_tarball(tgz: &Path, dest_dir: &Path) -> Result<()> {
    let status = Command::new("tar")
        .args([
            "-xzf",
            tgz.to_string_lossy().as_ref(),
            "-C",
            dest_dir.to_string_lossy().as_ref(),
        ])
        .status()
        .map_err(|e| BrokreError::Runtime(format!("tar not found: {e}")))?;
    if !status.success() {
        return Err(BrokreError::Runtime("tar extract failed".into()));
    }
    Ok(())
}

fn binary_name_in_dir(dir: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    let name = "brokre.exe";
    #[cfg(not(windows))]
    let name = "brokre";
    let path = dir.join(name);
    if path.is_file() {
        return Ok(path);
    }
    Err(BrokreError::Runtime(format!(
        "brokre binary missing in release tarball ({})",
        dir.display()
    )))
}

fn install_destination() -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .map_err(BrokreError::Io)?
        .canonicalize()
        .map_err(BrokreError::Io)?;
    if parent_writable(&exe) {
        return Ok(exe);
    }
    let user_bin = brokre_home().join("bin");
    fs::create_dir_all(&user_bin).map_err(BrokreError::Io)?;
    #[cfg(windows)]
    return Ok(user_bin.join("brokre.exe"));
    #[cfg(not(windows))]
    Ok(user_bin.join("brokre"))
}

fn parent_writable(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let probe = parent.join(format!(".brokre-upgrade-probe.{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn install_binary_atomically(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(BrokreError::Io)?;
    }
    let tmp = dest.with_extension(format!("new.{}", std::process::id()));
    fs::copy(src, &tmp).map_err(BrokreError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(BrokreError::Io)?;
    }
    fs::rename(&tmp, dest).map_err(BrokreError::Io)?;
    Ok(())
}

fn write_version_stamp(dest: &Path, version: &str) -> Result<()> {
    let stamp_dir = dest.parent().unwrap_or_else(|| Path::new("."));
    let stamp = stamp_dir.join(".version");
    fs::write(stamp, format!("{version}\n")).map_err(BrokreError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_github_tag() {
        let json = r#"{"tag_name": "v0.2.10", "name": "0.2.10"}"#;
        assert_eq!(parse_github_tag_name(json).as_deref(), Some("0.2.10"));
    }

    #[test]
    fn version_newer() {
        assert!(version_newer_than("0.2.10", "0.2.9"));
        assert!(!version_newer_than("0.2.9", "0.2.10"));
        assert!(!version_newer_than("0.2.10", "0.2.10"));
        assert!(version_newer_than("0.3.0", "0.2.99"));
    }

    #[test]
    fn normalize_strips_v() {
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
    }
}
