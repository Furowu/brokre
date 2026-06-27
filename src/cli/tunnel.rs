use crate::utils::errors::{BrokreError, Result};

pub fn run_agent(stdio: bool, version: bool) -> Result<()> {
    if version {
        println!(
            "brokre tunnel agent protocol {}",
            crate::tunnel::PROTOCOL_VERSION
        );
        return Ok(());
    }
    if !stdio {
        return Err(BrokreError::Cli(
            "`brokre tunnel agent` currently requires --stdio".into(),
        ));
    }
    crate::tunnel::agent::run_stdio()
}

pub fn run_doctor(bastion: String, json: bool) -> Result<()> {
    let report = crate::tunnel::client::doctor(&bastion)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "bastion": report.bastion,
                "agent_ok": report.agent_ok,
                "protocol_version": report.protocol_version,
                "arch": report.arch,
                "elapsed_ms": report.elapsed_ms,
            })
        );
    } else {
        println!("Tunnel agent OK: {}", report.bastion);
        println!("Protocol: {}", report.protocol_version);
        if let Some(arch) = report.arch {
            println!("Arch: {arch}");
        }
        println!("Elapsed: {} ms", report.elapsed_ms);
    }
    Ok(())
}

pub fn run_up(bastion: String, json: bool) -> Result<()> {
    run_doctor(bastion, json)
}
