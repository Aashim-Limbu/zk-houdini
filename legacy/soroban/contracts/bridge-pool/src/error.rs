use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    UnknownRoot = 3,
    NullifierAlreadyUsed = 4,
    InvalidProof = 5,
    UnknownDenomination = 6,
}
