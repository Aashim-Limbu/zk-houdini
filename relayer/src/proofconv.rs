//! Convert a snarkjs Groth16 proof (proof.json + public.json) into the byte
//! layout the Soroban verifier/`withdraw` expects.
//!   A = x || y                       (64 bytes)
//!   B = x_c1 || x_c0 || y_c1 || y_c0 (128 bytes, Soroban c1||c0 ordering)
//!   C = x || y                       (64 bytes)
//! All coords are 32-byte big-endian, lowercase hex, no 0x. A is NOT negated
//! (the on-chain verifier negates A internally for the pairing check).
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::Value;

/// Decimal string -> 64-char lowercase hex (32-byte big-endian). Errors if > 32 bytes.
pub fn dec_to_be32(decimal: &str) -> Result<String> {
    let n = BigUint::from_str_radix(decimal.trim(), 10).map_err(|e| anyhow!("bad decimal: {e}"))?;
    let be = n.to_bytes_be();
    if be.len() > 32 {
        return Err(anyhow!("value exceeds 32 bytes"));
    }
    let mut buf = [0u8; 32];
    buf[32 - be.len()..].copy_from_slice(&be);
    Ok(hex::encode(buf))
}

fn coord(v: &Value) -> Result<String> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected string coordinate"))?;
    dec_to_be32(s)
}

/// snarkjs proof.json -> (a, b, c) hex strings (lengths 128/256/128).
pub fn proof_abc(proof_json: &str) -> Result<(String, String, String)> {
    let v: Value = serde_json::from_str(proof_json)?;
    let (pa, pb, pc) = (&v["pi_a"], &v["pi_b"], &v["pi_c"]);
    let a = format!("{}{}", coord(&pa[0])?, coord(&pa[1])?);
    // pi_b = [[x_c0, x_c1], [y_c0, y_c1], [_, _]] ; Soroban wants x_c1||x_c0||y_c1||y_c0
    let b = format!(
        "{}{}{}{}",
        coord(&pb[0][1])?, coord(&pb[0][0])?, coord(&pb[1][1])?, coord(&pb[1][0])?
    );
    let c = format!("{}{}", coord(&pc[0])?, coord(&pc[1])?);
    Ok((a, b, c))
}

/// snarkjs public.json [root, nullifierHash, recipient, denomination]
/// -> (root_hex, nullifier_hash_hex, recipient_fr_hex, denom).
pub fn public_fields(public_json: &str) -> Result<(String, String, String, u32)> {
    let v: Value = serde_json::from_str(public_json)?;
    let arr = v.as_array().ok_or_else(|| anyhow!("public.json is not an array"))?;
    if arr.len() < 4 {
        return Err(anyhow!("expected 4 public signals, got {}", arr.len()));
    }
    let root = coord(&arr[0])?;
    let nh = coord(&arr[1])?;
    let recipient_fr = coord(&arr[2])?;
    let denom: u32 = arr[3]
        .as_str()
        .ok_or_else(|| anyhow!("denom not a string"))?
        .parse()
        .map_err(|e| anyhow!("bad denom: {e}"))?;
    Ok((root, nh, recipient_fr, denom))
}
