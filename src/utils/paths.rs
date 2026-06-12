use std::path::PathBuf;

pub fn brokre_home() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .expect("HOME not set");
    let p = home.join(".brokre");
    std::fs::create_dir_all(&p).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
    }
    p
}

pub fn vault_path() -> PathBuf {
    let p = brokre_home().join("vault");
    std::fs::create_dir_all(&p).ok();
    p.join("store.jsonl.enc")
}

pub fn run_dir() -> PathBuf {
    let p = brokre_home().join("run");
    std::fs::create_dir_all(&p).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
    }
    p
}

pub fn audit_path() -> PathBuf {
    let p = brokre_home().join("audit");
    std::fs::create_dir_all(&p).ok();
    p.join("audit.log")
}

pub fn profiles_dir() -> PathBuf {
    let p = brokre_home().join("profiles");
    std::fs::create_dir_all(&p).ok();
    p
}
