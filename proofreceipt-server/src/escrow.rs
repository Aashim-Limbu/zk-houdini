use crate::config::Config;
use crate::job;
use tokio::time::{sleep, Duration};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision { Prove, Decline }

/// Prove only when the contract's real (cheap-scanned) verdict equals what the buyer pinned.
pub fn decide(scanned: u32, expected: u32) -> Decision {
    if scanned == expected { Decision::Prove } else { Decision::Decline }
}

fn invoke_base(cfg: &Config) -> Vec<String> {
    let mut a = vec![
        "contract".into(), "invoke".into(),
        "--id".into(), cfg.settle_contract_id.clone(),
        "--source".into(), cfg.seller_key.clone(),
    ];
    if cfg.stellar_rpc_url.is_empty() {
        a.extend(["--network".into(), cfg.stellar_network.clone()]);
    } else {
        // Explicit RPC sidesteps a `stellar` quirk where `--network testnet` can
        // mis-resolve to "Invalid URL"; mirrors the buyer runner's escape hatch.
        a.extend([
            "--rpc-url".into(), cfg.stellar_rpc_url.clone(),
            "--network-passphrase".into(), cfg.stellar_network_passphrase.clone(),
        ]);
    }
    a.push("--".into());
    a
}

pub fn submit_proof_args(cfg: &Config, job_id_hex: &str, seal_hex: &str) -> Vec<String> {
    let mut a = invoke_base(cfg);
    a.extend(["submit_proof".into(),
        "--job_id".into(), job_id_hex.to_string(),
        "--seal".into(), seal_hex.to_string()]);
    a
}

pub fn claim_args(cfg: &Config, job_id_hex: &str) -> Vec<String> {
    let mut a = invoke_base(cfg);
    a.extend(["claim".into(), "--job_id".into(), job_id_hex.to_string()]);
    a
}

/// The challenge window is enforced on-chain: `claim` traps with ChallengeWindowOpen
/// (Error #7) until `claimable_at`. That is the only error worth retrying — every other
/// failure (already claimed, not proven) is terminal.
fn claim_retryable(err: &str) -> bool {
    err.contains("#7") || err.contains("ChallengeWindowOpen")
}

/// Poll-claim until the on-chain challenge window opens. Bounded so a stuck job
/// cannot loop forever; funds remain safely escrowed if it gives up.
async fn auto_claim_after_window(cfg: &Config, job_id_hex: &str) -> anyhow::Result<()> {
    for _ in 0..30 { // ~5 min at 10s
        sleep(Duration::from_secs(10)).await;
        match run_stellar(claim_args(cfg, job_id_hex)).await {
            Ok(()) => { eprintln!("[escrow] job {job_id_hex}: auto-claimed"); return Ok(()); }
            Err(e) if claim_retryable(&e.to_string()) => continue, // window not open yet
            Err(e) => return Err(e), // terminal
        }
    }
    anyhow::bail!("auto-claim gave up (challenge window never opened in time)")
}

/// One escrow job end to end. `wasm` is the buyer-supplied artifact; `expected_verdict`
/// is what the buyer pinned on-chain in open_job.
pub async fn handle_job(cfg: &Config, job_id_hex: String, wasm: Vec<u8>, expected_verdict: u32) -> anyhow::Result<()> {
    let scanned = wasm_policy::audit_verdict(&wasm)
        .map_err(|e| anyhow::anyhow!("scan failed: {e:?}"))?;
    if decide(scanned, expected_verdict) == Decision::Decline {
        // Don't pay the expensive prove cost for a job that can never be claimed.
        eprintln!("[escrow] job {job_id_hex}: scanned verdict {scanned} != pinned {expected_verdict} — declining");
        return Ok(());
    }
    let receipt = job::run_prover(&cfg.m0_host_path, wasm, cfg.prover_timeout_secs).await?;
    run_stellar(submit_proof_args(cfg, &job_id_hex, &receipt.seal)).await?;
    eprintln!("[escrow] job {job_id_hex}: submitted proof");
    if cfg.auto_claim {
        let cfg = cfg.clone();
        let job = job_id_hex.clone();
        tokio::spawn(async move {
            if let Err(e) = auto_claim_after_window(&cfg, &job).await {
                eprintln!("[escrow] job {job}: auto-claim failed: {e}");
            }
        });
    }
    Ok(())
}

async fn run_stellar(args: Vec<String>) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("stellar").args(&args).output().await?;
    if !out.status.success() {
        anyhow::bail!("stellar {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

// ── HTTP handler ───────────────────────────────────────────────────────────────

use crate::AppState;
use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct EscrowJobReq {
    pub job_id_hex: String,
    /// base64 of the raw WASM artifact bytes.
    pub artifact_b64: String,
    pub expected_verdict: u32,
}

pub async fn post_escrow_job(
    State(st): State<AppState>,
    Json(req): Json<EscrowJobReq>,
) -> Response {
    // Decode the artifact up front (bad base64 → 400, no work done).
    let wasm = match STANDARD.decode(req.artifact_b64.trim()) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"artifact_b64 not valid base64"}))).into_response(),
    };

    // Spawn the (slow) escrow worker; respond 202 immediately.
    let cfg: Arc<Config> = st.cfg.clone();
    let sem = st.prover_sem.clone();
    let job_id_hex = req.job_id_hex.clone();
    let expected_verdict = req.expected_verdict;
    tokio::spawn(async move {
        // Serialize proves (each peaks ~8GB) so concurrent requests can't OOM the box.
        let _permit = match sem.acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                eprintln!("[escrow] job {job_id_hex}: prover semaphore closed — dropping");
                return;
            }
        };
        if let Err(e) = handle_job(&cfg, job_id_hex.clone(), wasm, expected_verdict).await {
            eprintln!("[escrow] job {job_id_hex}: error: {e}");
        }
    });

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "accepted": true, "job_id_hex": req.job_id_hex }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> crate::config::Config {
        crate::config::Config::from_toml_str(
            r#"
            pay_to = "GSELLER"
            amount = "100000"
            oz_api_key = "k"
            image_id = "00"
            verifier_id = "CV"
            m0_host_path = "/bin/true"
            settle_contract_id = "CID123"
            seller_key = "seller"
            stellar_network = "testnet"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn decide_prove_only_on_match() {
        assert!(matches!(decide(0, 0), Decision::Prove));
        assert!(matches!(decide(2, 0), Decision::Decline)); // dirty, buyer wanted clean
        assert!(matches!(decide(0, 2), Decision::Decline)); // mismatch
    }

    #[test]
    fn submit_proof_args_shape() {
        let cfg = test_cfg();
        let a = submit_proof_args(&cfg, "ab12", "ffaa");
        // stellar contract invoke --id <CID> --source <key> --network testnet -- submit_proof --job_id ab12 --seal ffaa
        assert!(a.windows(2).any(|w| w == ["--id", "CID123"]));
        assert!(a.contains(&"submit_proof".to_string()));
        assert!(a.windows(2).any(|w| w == ["--job_id", "ab12"]));
        assert!(a.windows(2).any(|w| w == ["--seal", "ffaa"]));
        // default (no rpc_url) keeps the network alias form
        assert!(a.windows(2).any(|w| w == ["--network", "testnet"]));
        assert!(!a.iter().any(|s| s == "--rpc-url"));
    }

    #[test]
    fn claim_retryable_only_on_challenge_window() {
        assert!(claim_retryable("stellar invoke failed: Error(Contract, #7)"));
        assert!(claim_retryable("HostError ChallengeWindowOpen"));
        assert!(!claim_retryable("Error(Contract, #6)")); // JobNotProven — terminal
        assert!(!claim_retryable("anything else")); // terminal
    }

    #[test]
    fn invoke_uses_explicit_rpc_when_configured() {
        let mut cfg = test_cfg();
        cfg.stellar_rpc_url = "https://soroban-testnet.stellar.org".into();
        cfg.stellar_network_passphrase = "Test SDF Network ; September 2015".into();
        let a = submit_proof_args(&cfg, "ab12", "ffaa");
        assert!(a.windows(2).any(|w| w == ["--rpc-url", "https://soroban-testnet.stellar.org"]));
        assert!(a.windows(2).any(|w| w == ["--network-passphrase", "Test SDF Network ; September 2015"]));
        assert!(!a.iter().any(|s| s == "--network")); // alias form suppressed
        assert!(a.contains(&"submit_proof".to_string()));
    }
}
