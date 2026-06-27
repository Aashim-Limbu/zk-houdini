use relayer::proofconv::{dec_to_be32, proof_abc, public_fields};

#[test]
fn dec_to_be32_pads_and_rejects_overflow() {
    assert_eq!(dec_to_be32("0").unwrap(), "0".repeat(64));
    assert_eq!(dec_to_be32("255").unwrap(), format!("{}ff", "0".repeat(62)));
    assert_eq!(dec_to_be32("255").unwrap().len(), 64);
    // 2^256 does not fit in 32 bytes
    let two_256 = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    assert!(dec_to_be32(two_256).is_err());
}

#[test]
fn proof_abc_has_right_lengths_and_is_hex() {
    let p = std::fs::read_to_string("../artifacts/circuit/proof.json").unwrap();
    let (a, b, c) = proof_abc(&p).unwrap();
    assert_eq!(a.len(), 128);
    assert_eq!(b.len(), 256);
    assert_eq!(c.len(), 128);
    assert!(a.chars().chain(b.chars()).chain(c.chars()).all(|ch| ch.is_ascii_hexdigit()));
}

#[test]
fn public_fields_match_known_artifacts() {
    let pj = std::fs::read_to_string("../artifacts/circuit/public.json").unwrap();
    let (root, _nh, rfr, denom) = public_fields(&pj).unwrap();
    // anchored root 0012f414...70bd86d4 ; denom 10 ; recipient_fr from public[2]
    assert!(root.ends_with("70bd86d4"));
    assert_eq!(denom, 10);
    assert_eq!(rfr, dec_to_be32("103929005307927756724354605802047639613112342136").unwrap());
}
