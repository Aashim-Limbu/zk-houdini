#![no_std]
mod error;
mod storage;
#[cfg(test)]
mod test;

use error::Error;
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, BytesN, Env};
use storage::{DataKey, Job, Status};

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

    #[allow(clippy::too_many_arguments)]
    pub fn open_job(
        env: Env,
        job_id: BytesN<32>,
        buyer: Address,
        seller: Address,
        token_addr: Address,
        amount: i128,
        expected_input_hash: BytesN<32>,
        expected_image_id: BytesN<32>,
        challenge_secs: u64,
    ) -> Result<(), Error> {
        buyer.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        if storage::has_job(&env, &job_id) {
            return Err(Error::JobExists);
        }

        token::TokenClient::new(&env, &token_addr)
            .transfer(&buyer, &env.current_contract_address(), &amount);

        let job = Job {
            buyer,
            seller,
            token: token_addr,
            amount,
            expected_input_hash,
            expected_image_id,
            challenge_secs,
            verdict: 0,
            claimable_at: 0,
            status: Status::Open,
        };
        storage::set_job(&env, &job_id, &job);
        env.events().publish((symbol_short!("opened"), job_id), amount);
        Ok(())
    }
}
