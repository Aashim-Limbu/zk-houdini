#![no_std]
#![allow(unused_imports)]
mod error;
mod storage;
#[cfg(test)]
mod test;

use error::Error;
use storage::{DataKey, ROOT_HISTORY_SIZE};
use soroban_sdk::{
    contract, contractimpl, token, vec,
    crypto::bn254::Bn254Fr,
    Address, BytesN, Env, U256, Vec,
};
use contract_types::Groth16Proof;

// Cross-contract client for the verifier (matches its `verify` signature).
mod verifier_iface {
    use soroban_sdk::{contractclient, crypto::bn254::Bn254Fr, Env, Vec};
    use contract_types::{Groth16Error, Groth16Proof};

    #[contractclient(name = "VerifierClient")]
    pub trait Verifier {
        fn verify(
            env: Env,
            proof: Groth16Proof,
            public_inputs: Vec<Bn254Fr>,
        ) -> Result<bool, Groth16Error>;
    }
}
use verifier_iface::VerifierClient;

#[contract]
pub struct Pool;

#[contractimpl]
impl Pool {
    pub fn initialize(
        env: Env,
        admin: Address,
        relayer: Address,
        verifier: Address,
        token: Address,
        denoms: Vec<u32>,
        amounts: Vec<i128>,
    ) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error(&env, Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Relayer, &relayer);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage().instance().set(&DataKey::Token, &token);
        for (i, d) in denoms.iter().enumerate() {
            let amt = amounts.get(i as u32).unwrap();
            env.storage().instance().set(&DataKey::DenomAmount(d), &amt);
        }
    }

    pub fn get_verifier(env: Env) -> Result<Address, Error> { storage::get_verifier(&env) }
    pub fn get_token(env: Env) -> Result<Address, Error> { storage::get_token(&env) }
    pub fn get_relayer(env: Env) -> Result<Address, Error> { storage::get_relayer(&env) }
    pub fn get_denom_amount(env: Env, denom: u32) -> Result<i128, Error> {
        storage::get_denom_amount(&env, denom)
    }
    pub fn get_roots(env: Env, denom: u32) -> Vec<BytesN<32>> { storage::get_roots(&env, denom) }
    pub fn is_nullifier_used(env: Env, nh: BytesN<32>) -> bool {
        storage::is_nullifier_used(&env, &nh)
    }

    /// Anchor a recent EVM Merkle root into the denom's root window. Backing-relayer only.
    pub fn update_root(env: Env, denom: u32, root: BytesN<32>) -> Result<(), Error> {
        let relayer = storage::get_relayer(&env)?;
        relayer.require_auth();
        storage::get_denom_amount(&env, denom)?; // validate denom configured
        storage::push_root(&env, denom, &root);
        env.events().publish((soroban_sdk::symbol_short!("root"), denom), root);
        Ok(())
    }

    pub fn is_known_root(env: Env, denom: u32, root: BytesN<32>) -> bool {
        storage::is_known_root(&env, denom, &root)
    }

    /// Withdraw: verify a Groth16 proof of Merkle membership + nullifier, then
    /// release `denom` worth of the pool's SAC token to `recipient`.
    /// Public input vector order: [root, nullifierHash, recipient_fr, denomination].
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        env: Env,
        proof: Groth16Proof,
        root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        recipient_fr: BytesN<32>,
        recipient: Address,
        denom: u32,
    ) -> Result<(), Error> {
        let amount = storage::get_denom_amount(&env, denom)?;

        if !storage::is_known_root(&env, denom, &root) {
            return Err(Error::UnknownRoot);
        }
        if storage::is_nullifier_used(&env, &nullifier_hash) {
            return Err(Error::NullifierAlreadyUsed);
        }

        let denom_bytes = u32_to_fr_bytes(&env, denom);
        let public_inputs: Vec<Bn254Fr> = vec![
            &env,
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &root.clone().into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &nullifier_hash.clone().into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &recipient_fr.into())),
            Bn254Fr::from_u256(U256::from_be_bytes(&env, &denom_bytes.into())),
        ];

        let verifier = storage::get_verifier(&env)?;
        let vclient = VerifierClient::new(&env, &verifier);
        let ok = vclient.verify(&proof, &public_inputs);
        if !ok {
            return Err(Error::InvalidProof);
        }

        storage::mark_nullifier_used(&env, &nullifier_hash);

        let token = storage::get_token(&env)?;
        let sac = token::StellarAssetClient::new(&env, &token);
        sac.mint(&recipient, &amount);

        env.events().publish(
            (soroban_sdk::symbol_short!("withdraw"), denom),
            (nullifier_hash, recipient, amount),
        );
        Ok(())
    }
}

/// Encode a u32 denomination index as a 32-byte big-endian field element.
fn u32_to_fr_bytes(env: &Env, v: u32) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&v.to_be_bytes());
    BytesN::from_array(env, &b)
}

fn panic_with_error(env: &Env, e: Error) -> ! {
    soroban_sdk::panic_with_error!(env, e)
}
