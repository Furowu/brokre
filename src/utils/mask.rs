//! Redact secrets from argv fragments before writing to the audit log.
//! Command structure is preserved; only values after sensitive flags are masked.

const REDACTED: &str = "<REDACTED>";

/// Flag tokens whose following argv value may contain a password.
const SENSITIVE_FLAGS: &[&str] = &[
    "-p",
    "-P",
    "--password",
    "--pass",
    "--passphrase",
    "--key-passphrase",
];

/// Env-style prefixes whose value may contain a password.
const SENSITIVE_ENV_PREFIXES: &[&str] = &["PGPASSWORD=", "MYSQL_PWD=", "MYSQL_PASSWORD="];

fn is_sensitive_flag(token: &str) -> bool {
    SENSITIVE_FLAGS.contains(&token)
}

fn redact_value(_s: &str) -> String {
    REDACTED.to_string()
}

fn looks_like_pem(s: &str) -> bool {
    s.contains("-----BEGIN ")
}

fn redact_single_arg(arg: &str) -> String {
    if looks_like_pem(arg) {
        return "<REDACTED:key>".into();
    }
    for prefix in SENSITIVE_ENV_PREFIXES {
        if let Some(rest) = arg.strip_prefix(prefix) {
            return format!("{prefix}{}", redact_value(rest));
        }
    }
    if let Some((name, value)) = arg.split_once('=') {
        let flag = name.trim();
        if is_sensitive_flag(flag) || SENSITIVE_FLAGS.contains(&flag) {
            return format!("{name}={}", redact_value(value));
        }
    }
    arg.to_string()
}

/// Redact argv for audit logging. Most tokens are kept verbatim so operators can
/// see which command ran; values after password flags and PEM material are masked.
pub fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push(redact_value(arg));
            redact_next = false;
            continue;
        }
        if is_sensitive_flag(arg) {
            redact_next = true;
            out.push(arg.clone());
            continue;
        }
        out.push(redact_single_arg(arg));
    }
    out
}

/// Legacy helper — prefer [`redact_args`] for argv slices.
pub fn redact(s: &str) -> String {
    redact_single_arg(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_remote_command_args() {
        let args = vec![
            "-tt".into(),
            "user@host".into(),
            "uname".into(),
            "-a".into(),
        ];
        assert_eq!(
            redact_args(&args),
            vec!["-tt", "user@host", "uname", "-a"]
        );
    }

    #[test]
    fn redacts_password_flag_value() {
        let args = vec![
            "mysql".into(),
            "-p".into(),
            "s3cret".into(),
            "-e".into(),
            "SHOW TABLES".into(),
        ];
        assert_eq!(
            redact_args(&args),
            vec!["mysql", "-p", REDACTED, "-e", "SHOW TABLES"]
        );
    }

    #[test]
    fn redacts_inline_password_flag() {
        let args = vec!["--password=topsecret".into(), "status".into()];
        assert_eq!(
            redact_args(&args),
            vec![format!("--password={REDACTED}"), "status".into()]
        );
    }

    #[test]
    fn redacts_pem_material() {
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(redact_args(&[pem.into()]), vec!["<REDACTED:key>"]);
    }
}
