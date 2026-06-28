#![no_std]
mod error;
mod storage;
#[cfg(test)]
mod test;

use error::Error;
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Bytes, BytesN, Env};
use storage::{DataKey, Job, Status};
use risc0_interface::RiscZeroVerifierClient;

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
        expected_verdict: u32,
        reclaim_secs: u64,
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

        let reclaim_after = env.ledger().timestamp().saturating_add(reclaim_secs);
        let job = Job {
            buyer,
            seller,
            token: token_addr,
            amount,
            expected_input_hash,
            expected_image_id,
            expected_verdict,
            challenge_secs,
            verdict: 0,
            claimable_at: 0,
            reclaim_after,
            status: Status::Open,
        };
        storage::set_job(&env, &job_id, &job);
        env.events().publish((symbol_short!("opened"), job_id), amount);
        Ok(())
    }

    pub fn submit_proof(env: Env, job_id: BytesN<32>, seal: Bytes) -> Result<(), Error> {
        let mut job = storage::get_job(&env, &job_id)?;
        if job.status != Status::Open {
            return Err(Error::JobNotOpen);
        }
        job.seller.require_auth();

        // Journal is rebuilt from the buyer's PINNED (input_hash, expected_verdict).
        // verify() only succeeds if the guest committed exactly this verdict, so a
        // dirty contract (real verdict != pinned) can never produce a claimable proof.
        let mut buf = Bytes::from_array(&env, &job.expected_input_hash.to_array());
        buf.extend_from_array(&job.expected_verdict.to_le_bytes());
        let journal_digest: BytesN<32> = env.crypto().sha256(&buf).to_bytes();

        let verifier = storage::get_verifier(&env)?;
        RiscZeroVerifierClient::new(&env, &verifier)
            .verify(&seal, &job.expected_image_id, &journal_digest);

        job.verdict = job.expected_verdict;
        job.claimable_at = env.ledger().timestamp().saturating_add(job.challenge_secs);
        job.status = Status::Proven;
        storage::set_job(&env, &job_id, &job);
        env.events().publish((symbol_short!("proven"), job_id), (job.verdict, job.claimable_at));
        Ok(())
    }

    pub fn claim(env: Env, job_id: BytesN<32>) -> Result<(), Error> {
        let mut job = storage::get_job(&env, &job_id)?;
        if job.status != Status::Proven {
            return Err(Error::JobNotProven);
        }
        if env.ledger().timestamp() < job.claimable_at {
            return Err(Error::ChallengeWindowOpen);
        }
        job.seller.require_auth();

        token::TokenClient::new(&env, &job.token)
            .transfer(&env.current_contract_address(), &job.seller, &job.amount);

        job.status = Status::Claimed;
        storage::set_job(&env, &job_id, &job);
        env.events().publish((symbol_short!("claimed"), job_id), job.amount);
        Ok(())
    }

    pub fn buyer_reclaim(env: Env, job_id: BytesN<32>) -> Result<(), Error> {
        let mut job = storage::get_job(&env, &job_id)?;
        if job.status != Status::Open {
            return Err(Error::JobNotOpen);
        }
        if env.ledger().timestamp() < job.reclaim_after {
            return Err(Error::ReclaimTooEarly);
        }
        job.buyer.require_auth();

        token::TokenClient::new(&env, &job.token)
            .transfer(&env.current_contract_address(), &job.buyer, &job.amount);

        job.status = Status::Reclaimed;
        storage::set_job(&env, &job_id, &job);
        env.events().publish((symbol_short!("reclaimed"), job_id), job.amount);
        Ok(())
    }
}
