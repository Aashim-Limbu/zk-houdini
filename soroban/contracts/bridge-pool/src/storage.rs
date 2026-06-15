use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};
use crate::error::Error;

pub const ROOT_HISTORY_SIZE: u32 = 30;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Verifier,
    Token,
    Relayer,
    Roots(u32),
    Nullifier(BytesN<32>),
    DenomAmount(u32),
}

pub fn get_admin(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Admin).ok_or(Error::NotInitialized)
}
pub fn get_verifier(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Verifier).ok_or(Error::NotInitialized)
}
pub fn get_token(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Token).ok_or(Error::NotInitialized)
}
pub fn get_relayer(env: &Env) -> Result<Address, Error> {
    env.storage().instance().get(&DataKey::Relayer).ok_or(Error::NotInitialized)
}
pub fn get_denom_amount(env: &Env, denom: u32) -> Result<i128, Error> {
    env.storage().instance().get(&DataKey::DenomAmount(denom)).ok_or(Error::UnknownDenomination)
}
pub fn get_roots(env: &Env, denom: u32) -> Vec<BytesN<32>> {
    env.storage().persistent().get(&DataKey::Roots(denom)).unwrap_or(Vec::new(env))
}
pub fn set_roots(env: &Env, denom: u32, roots: &Vec<BytesN<32>>) {
    env.storage().persistent().set(&DataKey::Roots(denom), roots);
}
pub fn is_nullifier_used(env: &Env, nh: &BytesN<32>) -> bool {
    env.storage().persistent().has(&DataKey::Nullifier(nh.clone()))
}
pub fn mark_nullifier_used(env: &Env, nh: &BytesN<32>) {
    env.storage().persistent().set(&DataKey::Nullifier(nh.clone()), &());
}

/// Push a root into the denom's ring buffer, capping at ROOT_HISTORY_SIZE (drops oldest). Newest last.
pub fn push_root(env: &Env, denom: u32, root: &BytesN<32>) {
    let mut roots = get_roots(env, denom);
    if roots.len() >= ROOT_HISTORY_SIZE {
        roots.remove(0);
    }
    roots.push_back(root.clone());
    set_roots(env, denom, &roots);
}

pub fn is_known_root(env: &Env, denom: u32, root: &BytesN<32>) -> bool {
    let roots = get_roots(env, denom);
    roots.iter().any(|r| &r == root)
}
