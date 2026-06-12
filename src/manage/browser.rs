use std::process::Command;

/// Open a URL in the user's default browser (local only).
pub fn open_browser(url: &str) -> std::io::Result<()> {
    if cfg!(target_os = "macos") {
        Command::new("open").arg(url).status().map(|_| ())
    } else if cfg!(target_os = "linux") {
        Command::new("xdg-open").arg(url).status().map(|_| ())
    } else if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
            .map(|_| ())
    } else {
        let _ = url;
        Ok(())
    }
}
