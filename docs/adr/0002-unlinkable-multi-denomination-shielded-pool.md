# Privacy & value model: unlinkable, multi-denomination shielded pool (lock-and-mint)

The bridge is an unlinkable shielded pool (Tornado-style): a deposit records a **commitment**; a withdrawal proves Merkle membership of an unspent commitment and publishes a **nullifier hash**, breaking the deposit↔withdrawal link for everyone — including the relayer. Value moves by **lock-and-mint**: lock test-USDC on Sepolia, mint/release a bridged Soroban token on withdrawal.

Amounts use a **small fixed set of denominations**, not arbitrary amounts. This was a deliberate reversal of an initial "arbitrary amounts" instinct: arbitrary *public* amounts are a fingerprint (a withdrawal of 7.3 re-links to the unique 7.3 deposit), which would silently break the unlinkability the product requires. Confidential arbitrary amounts (Zcash/Aztec-style hidden values + range proofs) preserve unlinkability but are 3–5× the circuit and the wrong risk on a hackathon clock.

**Multi-denomination is realized as one independent pool per denomination**, each its own anonymity set. Arbitrary totals are achieved by combining notes across denominations.
