//! Thin binary around [`cipherlayer_vaultd::Daemon`] — all daemon logic
//! lives in the library so the IPC boundary is integration-testable
//! (external re-audit, 2026-07-20).

use cipherlayer_vault::{TestSigner, Vault, ANVIL_DEV_KEYS};
use cipherlayer_vaultd::Daemon;
use std::path::PathBuf;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let socket_path: PathBuf = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CIPHERLAYER_VAULT_SOCKET").ok())
        .unwrap_or_else(|| "./data/vaultd/vault.sock".into())
        .into();
    let key = std::env::var("CIPHERLAYER_TEST_SIGNER_KEY")
        .unwrap_or_else(|_| ANVIL_DEV_KEYS[0].to_string());
    let signer = TestSigner::from_dev_key(&key).map_err(|e| {
        // Refusing a possibly-real key is the point; say so and stop.
        std::io::Error::other(format!("refusing to start: {e}"))
    })?;
    let mut daemon = Daemon::new(Vault::new(signer));
    daemon.run(&socket_path).await
}
