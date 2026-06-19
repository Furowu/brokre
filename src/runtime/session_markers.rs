//! Marker protocol for MCP persistent elevated PTY sessions.

pub const READY: &str = "__BROKRE_READY__";
pub const BEGIN: &str = "__BROKRE_BEGIN__";
pub const END: &str = "__BROKRE_END__";

/// Wrap a user command for execution inside a persistent shell.
pub fn wrap_command(command: &str) -> String {
    format!(
        "printf '{begin}\\n'; {cmd}; printf '\\n{end}%s\\n' $?\n",
        begin = BEGIN,
        cmd = command,
        end = END,
    )
}

/// Parse command output between markers; returns (stdout, exit_code).
pub fn parse_command_output(buf: &str) -> Option<(String, i32)> {
    let begin = buf.find(BEGIN)?;
    let after_begin = &buf[begin + BEGIN.len()..];
    let after_begin = after_begin.strip_prefix('\n').unwrap_or(after_begin);
    let end_pos = after_begin.rfind(END)?;
    let stdout = after_begin[..end_pos].trim_end_matches('\n').to_string();
    let tail = &after_begin[end_pos + END.len()..];
    let code_str = tail.trim().lines().next()?.trim();
    let exit_code = code_str.parse().ok()?;
    Some((stdout, exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_between_markers() {
        let buf = "noise\n__BROKRE_BEGIN__\nhello\nworld\n__BROKRE_END__0\n";
        let (out, code) = parse_command_output(buf).unwrap();
        assert_eq!(out, "hello\nworld");
        assert_eq!(code, 0);
    }

    #[test]
    fn wrap_includes_markers() {
        let w = wrap_command("whoami");
        assert!(w.contains("__BROKRE_BEGIN__"));
        assert!(w.contains("whoami"));
        assert!(w.contains("__BROKRE_END__"));
    }
}
