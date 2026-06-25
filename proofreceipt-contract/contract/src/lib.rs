#![no_std]
mod error;
mod storage;
#[cfg(test)]
mod test;

use error::Error;
use storage::DataKey;
use storage::Job;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct ProofReceipt;

#[contractimpl]
impl ProofReceipt {
    pub fn initialize(env: Env, verifier: Address) {
        if env.storage().instance().has(&DataKey::Verifier) {
            soroban_sdk::panic_with_error!(&env, Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Verifier, &verifier);
    }

    pub fn get_verifier(env: Env) -> Result<Address, Error> {
        storage::get_verifier(&env)
    }

    pub fn get_job(env: Env, job_id: BytesN<32>) -> Result<Job, Error> {
        storage::get_job(&env, &job_id)
    }
}
