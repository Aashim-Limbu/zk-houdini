#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Env};
use crate::{ProofReceipt, ProofReceiptClient};
use soroban_sdk::{token, BytesN};

fn make_token<'a>(env: &'a Env, admin: &Address) -> (Address, token::StellarAssetClient<'a>, token::TokenClient<'a>) {
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let addr = sac.address();
    (addr.clone(), token::StellarAssetClient::new(env, &addr), token::TokenClient::new(env, &addr))
}

#[test]
fn initialize_sets_verifier() {
    let env = Env::default();
    let verifier = Address::generate(&env);
    let id = env.register(ProofReceipt, ());
    let client = ProofReceiptClient::new(&env, &id);
    client.initialize(&verifier);
    assert_eq!(client.get_verifier(), verifier);
}

#[test]
fn open_job_escrows_funds() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let (token_addr, mint, tok) = make_token(&env, &admin);
    mint.mint(&buyer, &1000);

    let id = env.register(ProofReceipt, ());
    let client = ProofReceiptClient::new(&env, &id);
    client.initialize(&Address::generate(&env));

    let job_id = BytesN::from_array(&env, &[7u8; 32]);
    let ih = BytesN::from_array(&env, &[1u8; 32]);
    let img = BytesN::from_array(&env, &[2u8; 32]);
    client.open_job(&job_id, &buyer, &seller, &token_addr, &100, &ih, &img, &60);

    assert_eq!(tok.balance(&buyer), 900);
    assert_eq!(tok.balance(&id), 100);
    let job = client.get_job(&job_id);
    assert_eq!(job.status, crate::storage::Status::Open);
    assert_eq!(job.amount, 100);
}

#[test]
#[should_panic]
fn open_job_rejects_duplicate_id() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let (token_addr, mint, _tok) = make_token(&env, &admin);
    mint.mint(&buyer, &1000);
    let id = env.register(ProofReceipt, ());
    let client = ProofReceiptClient::new(&env, &id);
    client.initialize(&Address::generate(&env));
    let job_id = BytesN::from_array(&env, &[7u8; 32]);
    let ih = BytesN::from_array(&env, &[1u8; 32]);
    let img = BytesN::from_array(&env, &[2u8; 32]);
    client.open_job(&job_id, &buyer, &seller, &token_addr, &100, &ih, &img, &60);
    client.open_job(&job_id, &buyer, &seller, &token_addr, &100, &ih, &img, &60);
}
