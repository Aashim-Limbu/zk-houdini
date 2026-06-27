import {
  Contract, TransactionBuilder, BASE_FEE, Networks, nativeToScVal, rpc,
} from "@stellar/stellar-sdk";

const RPC_URL = "https://soroban-testnet.stellar.org";

/**
 * Read-only verify of a receipt against the deployed RISC Zero verifier router.
 * Returns true if the proof verifies (void return), false if the contract traps.
 * @param verifierId  the CCR6... router contract id
 * @param sourceAddr  any funded testnet G-account (for a valid sequence; never signed/submitted)
 */
export async function verifyOnChain(
  verifierId: string,
  sourceAddr: string,
  seal: Uint8Array,
  imageId: Uint8Array,     // 32 bytes
  journalDigest: Uint8Array, // 32 bytes (sha256 of journal)
): Promise<boolean> {
  const server = new rpc.Server(RPC_URL);
  const contract = new Contract(verifierId);
  const op = contract.call(
    "verify",
    nativeToScVal(Buffer.from(seal), { type: "bytes" }),
    nativeToScVal(Buffer.from(imageId), { type: "bytes" }),
    nativeToScVal(Buffer.from(journalDigest), { type: "bytes" }),
  );
  const account = await server.getAccount(sourceAddr);
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: Networks.TESTNET })
    .addOperation(op).setTimeout(30).build();
  const sim = await server.simulateTransaction(tx);
  // The verifier traps (contract error / WASM panic / unreachable) on an invalid proof, all
  // of which surface as a simulation error → the proof did NOT verify. Genuine transport/RPC
  // failures throw from `simulateTransaction` itself (caught by the caller), not here.
  if (rpc.Api.isSimulationError(sim)) return false;
  return rpc.Api.isSimulationSuccess(sim);
}
