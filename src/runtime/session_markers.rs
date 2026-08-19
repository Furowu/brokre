//! Marker protocol for MCP persistent elevated PTY sessions.

use uuid::Uuid;

pub const READY: &str = "__BROKRE_READY__";
pub const BEGIN: &str = "__BROKRE_BEGIN__";
pub const END: &str = "__BROKRE_END__";

/// Remote shell setup after READY: disable echo, widen the TTY, drop PS1.
pub const HYGIENE_COMMAND: &str =
    "stty -echo 2>/dev/null; stty cols 1024 rows 24 2>/dev/null; PS1=; export PS1=; unset PROMPT_COMMAND";

/// Wrapped remote command plus the unique begin/end tokens used to parse stdout.
pub struct WrappedCommand {
    pub line: String,
    pub begin: String,
    pub end: String,
}

impl WrappedCommand {
    pub fn parse(&self, buf: &str) -> Option<(String, i32)> {
        parse_command_output(buf, &self.begin, &self.end)
    }
}

pub fn new_marker_id() -> String {
    let hex = Uuid::new_v4().simple().to_string();
    hex[..16].to_string()
}

/// Wrap a user command for execution inside a persistent shell.
pub fn wrap_command(command: &str) -> WrappedCommand {
    wrap_command_with_id(command, &new_marker_id())
}

pub fn wrap_command_with_id(command: &str, id: &str) -> WrappedCommand {
    let begin = format!("{BEGIN}{id}");
    let end = format!("{END}{id}");
    let line = format!(
        "printf '%s\\n' '{begin}'; {cmd}; printf '%s %s\\n' '{end}' $?\n",
        begin = begin,
        cmd = command,
        end = end,
    );
    WrappedCommand { line, begin, end }
}

fn normalize_pty_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn parse_end_line(line: &str, end: &str) -> Option<i32> {
    let rest = line.strip_prefix(end)?;
    let rest = rest.strip_prefix(' ')?;
    rest.parse().ok()
}

/// Parse command output between whole-line markers; returns (stdout, exit_code).
///
/// Markers must occupy their own lines. Substring matches inside TTY echo of the
/// wrap command are ignored.
pub fn parse_command_output(buf: &str, begin: &str, end: &str) -> Option<(String, i32)> {
    let buf = normalize_pty_newlines(buf);
    let lines: Vec<&str> = buf.split('\n').collect();
    let begin_idx = lines.iter().position(|line| *line == begin)?;
    let (end_idx, exit_code) = lines
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, line)| parse_end_line(line, end).map(|code| (i, code)))?;
    if end_idx <= begin_idx {
        return None;
    }
    let stdout = lines[begin_idx + 1..end_idx].join("\n");
    Some((stdout.trim_end_matches('\n').to_string(), exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap() -> WrappedCommand {
        wrap_command_with_id("whoami", "deadbeefcafebabe")
    }

    #[test]
    fn parse_between_markers() {
        let w = wrap();
        let buf = format!("noise\n{}\nhello\nworld\n{} 0\n", w.begin, w.end);
        let (out, code) = w.parse(&buf).unwrap();
        assert_eq!(out, "hello\nworld");
        assert_eq!(code, 0);
    }

    #[test]
    fn wrap_includes_markers() {
        let w = wrap();
        assert_eq!(w.begin, "__BROKRE_BEGIN__deadbeefcafebabe");
        assert_eq!(w.end, "__BROKRE_END__deadbeefcafebabe");
        assert!(w.line.contains("whoami"));
        assert!(w
            .line
            .contains("printf '%s\\n' '__BROKRE_BEGIN__deadbeefcafebabe'"));
        assert!(w
            .line
            .contains("printf '%s %s\\n' '__BROKRE_END__deadbeefcafebabe' $?"));
        assert!(!w.line.contains("printf '__BROKRE_BEGIN__"));
    }

    #[test]
    fn wrap_command_uses_unique_ids() {
        let a = wrap_command("whoami");
        let b = wrap_command("whoami");
        assert_ne!(a.begin, b.begin);
        assert_ne!(a.end, b.end);
    }

    #[test]
    fn parse_strips_pty_echo_of_wrap() {
        let w = wrap();
        let buf = format!(
            "{}\r\n{}\r\nroot\r\n{} 0\r\n",
            w.line.trim_end(),
            w.begin,
            w.end
        );
        let (out, code) = w.parse(&buf).unwrap();
        assert_eq!(out, "root", "echo of wrap must not leak into stdout");
        assert_eq!(code, 0);
        assert!(!out.contains("printf"));
    }

    #[test]
    fn parse_strips_crlf_wrapper_tail_and_export() {
        let w = wrap_command_with_id(
            "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; kubectl get ns",
            "aabbccddeeff0011",
        );
        let buf = format!(
            "{}\r\n{}\r\nkube-system\r\n{} 0\r\n",
            w.line.trim_end(),
            w.begin,
            w.end
        );
        let (out, code) = w.parse(&buf).unwrap();
        assert_eq!(out, "kube-system");
        assert_eq!(code, 0);
        assert!(!out.contains("printf"));
        assert!(!out.contains("export KUBECONFIG"));
        assert!(!out.contains("__BROKRE_"));
    }

    #[test]
    fn parse_strips_wrapped_echo_fragments() {
        let w = wrap_command_with_id("./r sizing kube-reserved --apply", "1122334455667788");
        let echo = w
            .line
            .trim_end()
            .replace("kube-reserved", "kube\r\n-reserved");
        let buf = format!("{echo}\r\n{}\r\napplied\r\n{} 0\r\n", w.begin, w.end);
        let (out, _) = w.parse(&buf).unwrap();
        assert_eq!(out, "applied");
        assert!(!out.contains("-reserved"));
    }

    #[test]
    fn parse_strips_ps1_prefix_before_begin_line() {
        let w = wrap_command_with_id("cat /tmp/config.yaml", "99aabbccddeeff00");
        let buf = format!(
            "dev-hostdev-host\r\n{}\r\n{}\r\napiVersion: v1\r\nkind: Config\r\n{} 0\r\n",
            w.line.trim_end(),
            w.begin,
            w.end
        );
        let (out, _) = w.parse(&buf).unwrap();
        assert_eq!(out, "apiVersion: v1\nkind: Config");
        assert!(!out.contains("dev-host"));
        assert!(out.starts_with("apiVersion: v1"));
    }

    #[test]
    fn parse_keeps_literal_begin_inside_command_output() {
        let w = wrap_command_with_id("cat /tmp/notes", "cafebabedeadbeef");
        let buf = format!(
            "{}\n{}\n{BEGIN}\nfile body\n{} 0\n",
            w.line.trim_end(),
            w.begin,
            w.end
        );
        let (out, _) = w.parse(&buf).unwrap();
        assert_eq!(out, format!("{BEGIN}\nfile body"));
    }

    #[test]
    fn parse_returns_none_until_end_line() {
        let w = wrap();
        let buf = format!("{}\n{}\npartial\n", w.line.trim_end(), w.begin);
        assert!(w.parse(&buf).is_none());
    }

    #[test]
    fn hygiene_command_disables_echo_and_prompt() {
        assert!(HYGIENE_COMMAND.contains("stty -echo"));
        assert!(HYGIENE_COMMAND.contains("stty cols 1024"));
        assert!(HYGIENE_COMMAND.contains("PS1="));
        assert!(HYGIENE_COMMAND.contains("unset PROMPT_COMMAND"));
    }
}
