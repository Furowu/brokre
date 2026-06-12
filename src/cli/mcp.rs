use crate::mcp::run_mcp_server;
use crate::utils::errors::Result;

pub fn run() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| crate::utils::errors::BrokrError::Runtime(e.to_string()))?;
    rt.block_on(run_mcp_server())
}
