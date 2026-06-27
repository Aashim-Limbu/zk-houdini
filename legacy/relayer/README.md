# Relayer

Off-chain services for the zk-houdini bridge: a backing daemon (anchors EVM roots
into the Soroban pool) and a withdrawal HTTP server (serves Merkle paths and relays
withdrawal proofs).

## Build & test

    cargo test --manifest-path relayer/Cargo.toml

## Configure

    cp relayer/config.example.toml relayer/config.toml   # edit evm_rpc

All commands except `topic` need `--config relayer/config.toml`.

`log_window_blocks` (default 9) caps the block span per `eth_getLogs` call so the
daemon and `/path` work on free-tier RPCs (Alchemy free = 10-block range). Raise it
on a paid RPC for faster historical backfill.

`convert-proof` turns a snarkjs `proof.json` (+ `public.json`) into the `{a,b,c}`
JSON that `withdraw --proof` expects (G2 in c1||c0 order); add a `recipient`
address and POST it to `/withdraw`.

## Commands

    relayer --config relayer/config.toml backing            # run the backing daemon
    relayer --config relayer/config.toml serve              # run the withdrawal HTTP server
    relayer --config relayer/config.toml path --denom 10 --leaf-index 0
    relayer --config relayer/config.toml backing-once --denom 10 --root <hex>
    relayer topic
    relayer convert-proof --proof artifacts/circuit/proof.json --public artifacts/circuit/public.json

## HTTP API (serve)

- `GET  /health` -> `{ status, deposit_contract, pool_id, denoms }`
- `GET  /path?denom=<value>&leaf_index=<n>` -> `{ root, root_hex, path_elements, path_indices, leaf_index }`
- `POST /withdraw` `{ proof, root, nullifier_hash, recipient_fr, recipient, denom }` -> `{ tx_hash }`

`denom` is the pool **value** (1/10/100). See `docs/ARCHITECTURE.md`.

## e2e smoke

    RECIPIENT=G... ./relayer/scripts/e2e_smoke.sh
