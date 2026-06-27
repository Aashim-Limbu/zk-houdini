#![cfg(test)]
use crate::{Pool, PoolClient};
use soroban_sdk::{testutils::Address as _, vec, Address, Env};

fn setup(env: &Env) -> (PoolClient, Address, Address, Address, Address) {
    let admin = Address::generate(env);
    let relayer = Address::generate(env);
    let verifier = Address::generate(env);
    let token = Address::generate(env);
    let id = env.register(Pool, ());
    let client = PoolClient::new(env, &id);
    client.initialize(
        &admin,
        &relayer,
        &verifier,
        &token,
        &vec![env, 1u32, 10u32, 100u32],
        &vec![env, 1_0000000i128, 10_0000000, 100_0000000],
    );
    (client, admin, relayer, verifier, token)
}

#[test]
fn initialize_sets_config() {
    let env = Env::default();
    let (client, _admin, _r, verifier, token) = setup(&env);
    assert_eq!(client.get_verifier(), verifier);
    assert_eq!(client.get_token(), token);
    assert_eq!(client.get_denom_amount(&10u32), 10_0000000i128);
}

#[test]
#[should_panic]
fn double_initialize_panics() {
    let env = Env::default();
    let (client, admin, relayer, verifier, token) = setup(&env);
    client.initialize(
        &admin, &relayer, &verifier, &token,
        &vec![&env, 1u32], &vec![&env, 1i128],
    );
}

use soroban_sdk::BytesN;

fn root(env: &Env, b: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = b;
    BytesN::from_array(env, &a)
}

#[test]
fn relayer_can_anchor_root_and_it_is_known() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin, _relayer, _v, _t) = setup(&env);
    let r = root(&env, 7);
    client.update_root(&10u32, &r);
    assert!(client.is_known_root(&10u32, &r));
    assert!(!client.is_known_root(&10u32, &root(&env, 8)));
}

#[test]
fn ring_buffer_caps_at_30() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _a, _r, _v, _t) = setup(&env);
    for i in 1u8..=35 {
        client.update_root(&1u32, &root(&env, i));
    }
    assert_eq!(client.get_roots(&1u32).len(), 30);
    assert!(!client.is_known_root(&1u32, &root(&env, 1)));
    assert!(client.is_known_root(&1u32, &root(&env, 35)));
}

#[test]
#[should_panic]
fn non_relayer_cannot_anchor() {
    let env = Env::default();
    let (client, _a, _r, _v, _t) = setup(&env);
    client.update_root(&1u32, &root(&env, 1));
}

use contract_types::Groth16Proof;

mod mockverifier {
    use soroban_sdk::{contract, contractimpl, crypto::bn254::Bn254Fr, Env, Vec};
    use contract_types::{Groth16Error, Groth16Proof};

    #[contract]
    pub struct GoodVerifier;
    #[contractimpl]
    impl GoodVerifier {
        pub fn verify(_e: Env, _p: Groth16Proof, _i: Vec<Bn254Fr>) -> Result<bool, Groth16Error> { Ok(true) }
    }

    #[contract]
    pub struct BadVerifier;
    #[contractimpl]
    impl BadVerifier {
        pub fn verify(_e: Env, _p: Groth16Proof, _i: Vec<Bn254Fr>) -> Result<bool, Groth16Error> { Ok(false) }
    }
}

fn zero_proof(env: &Env) -> Groth16Proof {
    use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine};
    Groth16Proof {
        a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
        b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &[0u8; 128])),
        c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
    }
}

fn setup_withdraw<'a>(env: &'a Env, verifier: &Address) -> (PoolClient<'a>, Address, Address) {
    let admin = Address::generate(env);
    let relayer = Address::generate(env);
    let pool_id = env.register(Pool, ());
    let sac = env.register_stellar_asset_contract_v2(pool_id.clone());
    let token_addr = sac.address();
    let client = PoolClient::new(env, &pool_id);
    client.initialize(
        &admin, &relayer, verifier, &token_addr,
        &vec![env, 1u32, 10u32, 100u32],
        &vec![env, 1_0000000i128, 10_0000000, 100_0000000],
    );
    (client, pool_id, token_addr)
}

fn recipient_fr(env: &Env, recipient: &Address) -> BytesN<32> {
    let _ = recipient;
    BytesN::from_array(env, &[9u8; 32])
}

#[test]
fn withdraw_happy_path_mints_to_recipient() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, token_addr) = setup_withdraw(&env, &v);
    let denom = 10u32;
    let r = root(&env, 1);
    client.update_root(&denom, &r);
    let recipient = Address::generate(&env);
    let nh = root(&env, 42);
    client.withdraw(&zero_proof(&env), &r, &nh, &recipient_fr(&env, &recipient), &recipient, &denom);
    let token = soroban_sdk::token::TokenClient::new(&env, &token_addr);
    assert_eq!(token.balance(&recipient), 10_0000000i128);
    assert!(client.is_nullifier_used(&nh));
}

#[test]
#[should_panic]
fn withdraw_replay_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let denom = 1u32;
    let r = root(&env, 1);
    client.update_root(&denom, &r);
    let recipient = Address::generate(&env);
    let nh = root(&env, 5);
    client.withdraw(&zero_proof(&env), &r, &nh, &recipient_fr(&env, &recipient), &recipient, &denom);
    client.withdraw(&zero_proof(&env), &r, &nh, &recipient_fr(&env, &recipient), &recipient, &denom);
}

#[test]
#[should_panic]
fn withdraw_unknown_root_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::GoodVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let recipient = Address::generate(&env);
    client.withdraw(&zero_proof(&env), &root(&env, 99), &root(&env, 5), &recipient_fr(&env, &recipient), &recipient, &1u32);
}

#[test]
#[should_panic]
fn withdraw_bad_proof_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let v = env.register(mockverifier::BadVerifier, ());
    let (client, _pool, _t) = setup_withdraw(&env, &v);
    let denom = 1u32;
    let r = root(&env, 1);
    client.update_root(&denom, &r);
    let recipient = Address::generate(&env);
    client.withdraw(&zero_proof(&env), &r, &root(&env, 5), &recipient_fr(&env, &recipient), &recipient, &denom);
}
