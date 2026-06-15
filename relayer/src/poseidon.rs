//! Pinned Poseidon2 over BN254 — the project keystone (mixed-arity, validated 2026-06-15).
//! Field is zkhash's `FpBN256` (NOT `ark_bn254::Fr`; same modulus, different type).
//!   - compress(l,r)          = Perm2([l,r])[0] + l         (t=2, Merkle node)
//!   - hash2(nullifier,secret)= Perm3([nullifier,secret,0])[0] (t=3, commitment)
//!   - hash1(nullifier)       = Perm2([nullifier,0])[0]     (t=2, nullifierHash)
//! Cross-surface vectors: compress(1,2)=0x0e90..cea5b3, hash2(1,2)=0x2afac3..65bffd2,
//! hash1(1)=0x09546f..79b04d54  (== circom == Solidity).

use ark_ff::{BigInteger, PrimeField};
pub use zkhash::fields::bn256::FpBN256 as Fr;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::{
    POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3,
};

/// Width-2 permutation of [a,b] -> [s0,s1].
pub fn perm2(a: Fr, b: Fr) -> [Fr; 2] {
    let o = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2).permutation(&[a, b]);
    [o[0], o[1]]
}

/// Width-3 permutation of [a,b,c] -> [s0,s1,s2].
pub fn perm3(a: Fr, b: Fr, c: Fr) -> [Fr; 3] {
    let o = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3).permutation(&[a, b, c]);
    [o[0], o[1], o[2]]
}

/// Merkle internal node: Compress(l,r) = Perm2([l,r])[0] + l.
pub fn compress(l: Fr, r: Fr) -> Fr {
    perm2(l, r)[0] + l
}

/// commitment = Poseidon2(2)([nullifier, secret], dsep=0)  (t=3 sponge).
pub fn hash2(nullifier: Fr, secret: Fr) -> Fr {
    perm3(nullifier, secret, Fr::from(0u64))[0]
}

/// nullifierHash = Poseidon2(1)([nullifier], dsep=0)  (t=2 sponge).
pub fn hash1(nullifier: Fr) -> Fr {
    perm2(nullifier, Fr::from(0u64))[0]
}

/// 32-byte big-endian encoding of a field element.
pub fn to_be_bytes(x: &Fr) -> [u8; 32] {
    let mut v = x.into_bigint().to_bytes_be();
    while v.len() < 32 {
        v.insert(0, 0);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v[v.len() - 32..]);
    a
}

pub fn to_hex(x: &Fr) -> String {
    let mut s = String::from("0x");
    for b in to_be_bytes(x) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
