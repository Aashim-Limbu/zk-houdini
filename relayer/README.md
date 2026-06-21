# Relayer

Off-chain services for the zk-houdini bridge: a backing daemon (anchors EVM roots
into the Soroban pool) and a withdrawal HTTP server (serves Merkle paths and relays
withdrawal proofs).

## Build & test

    cargo test --manifest-path relayer/Cargo.toml

## Configure

    cp relayer/config.example.toml relayer/config.toml   # edit evm_rpc

All commands except `topic` need `--config relayer/config.toml`.

## Commands

    relayer --config relayer/config.toml backing            # run the backing daemon
    relayer --config relayer/config.toml serve              # run the withdrawal HTTP server
    relayer --config relayer/config.toml path --denom 10 --leaf-index 0
    relayer --config relayer/config.toml backing-once --denom 10 --root <hex>
    relayer topic

## HTTP API (serve)

- `GET  /health` -> `{ status, deposit_contract, pool_id, denoms }`
- `GET  /path?denom=<value>&leaf_index=<n>` -> `{ root, root_hex, path_elements, path_indices, leaf_index }`
- `POST /withdraw` `{ proof, root, nullifier_hash, recipient_fr, recipient, denom }` -> `{ tx_hash }`

`denom` is the pool **value** (1/10/100). See `docs/ARCHITECTURE.md`.

## e2e smoke

    RECIPIENT=G... ./relayer/scripts/e2e_smoke.sh
