use relayer::withdrawal::{denom_index_of, validate_withdraw, WithdrawRequest};

fn req(denom: u32) -> WithdrawRequest {
    WithdrawRequest {
        proof: "{}".into(),
        root: "0x01".into(),
        nullifier_hash: "0x02".into(),
        recipient_fr: "0x03".into(),
        recipient: "GABC".into(),
        denom,
    }
}

#[test]
fn maps_value_to_index() {
    let denoms = vec![1u32, 10, 100];
    assert_eq!(denom_index_of(&denoms, 1), Some(0));
    assert_eq!(denom_index_of(&denoms, 100), Some(2));
    assert_eq!(denom_index_of(&denoms, 7), None);
}

#[test]
fn validate_accepts_configured_denom() {
    let denoms = vec![1u32, 10, 100];
    assert!(validate_withdraw(&req(10), &denoms).is_ok());
}

#[test]
fn validate_rejects_unconfigured_denom() {
    let denoms = vec![1u32, 10, 100];
    assert!(validate_withdraw(&req(7), &denoms).is_err());
}

#[test]
fn validate_rejects_empty_field() {
    let denoms = vec![1u32, 10, 100];
    let mut r = req(10);
    r.recipient = "".into();
    assert!(validate_withdraw(&r, &denoms).is_err());
}
