use relayer::poseidon::{compress, hash1, hash2, perm2, to_hex, Fr};

#[test]
fn keystone_vectors_match_circom_and_solidity() {
    // Canonical cross-surface vectors (spike/poseidon2_vectors.json), validated 2026-06-15.
    assert_eq!(to_hex(&compress(Fr::from(1u64), Fr::from(2u64))),
        "0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b3", "compress(1,2) t=2");
    assert_eq!(to_hex(&hash2(Fr::from(1u64), Fr::from(2u64))),
        "0x2afac3bdc3663b71eefeecdf21b147d0ba7dd7a169a7757c05ed6bfb065bffd2", "hash2(1,2) t=3");
    assert_eq!(to_hex(&hash1(Fr::from(1u64))),
        "0x09546fe32f579f77c33ffb629a91ed18c4594804519846d143d3c1ba79b04d54", "hash1(1) t=2");
}

#[test]
fn compress_matches_identity() {
    let (l, r) = (Fr::from(7u64), Fr::from(9u64));
    assert_eq!(compress(l, r), perm2(l, r)[0] + l);
}
