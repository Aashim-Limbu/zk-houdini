#![cfg(test)]
use soroban_sdk::{testutils::Address as _, Address, Env};
use crate::{ProofReceipt, ProofReceiptClient};

#[test]
fn initialize_sets_verifier() {
    let env = Env::default();
    let verifier = Address::generate(&env);
    let id = env.register(ProofReceipt, ());
    let client = ProofReceiptClient::new(&env, &id);
    client.initialize(&verifier);
    assert_eq!(client.get_verifier(), verifier);
}
