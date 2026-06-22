// Real, public testnet deployment facts for zk-houdini. No secrets.
// Source of truth: deployments/testnet.env (committed). Keeps the footer and
// network chrome honest (Production bar: real content, no placeholders).

export const REPO_URL = "https://github.com/Aashim-Limbu/zk-houdini";

export const EVM = {
  chainId: 11155111,
  name: "Ethereum Sepolia",
  short: "Sepolia",
  pool: "0x4c781728f3f53f220c6f226610cd24d8b1e8e7ef",
  deployBlock: 11089276,
} as const;

export const STELLAR = {
  name: "Stellar Testnet",
  short: "Stellar",
  passphrase: "Test SDF Network ; September 2015",
  pool: "CDFQ5K2BPKB7BWNW2SJPGIIK5OOFQIR434MOX5YYBDKAN3M5CFVJKHR2",
  verifier: "CBXA7364AEVDQV2Z4CW7IUYSHO7JTETPUR6Y5FET2QAC5GWTNPN3ZGFH",
  zusdcSac: "CAIUOHVZ77RSCDBNWR3BCZPTWHPUXQRTQXSW4VE3HGC2M5PRPJNSFBRU",
} as const;

// pool denom id = USDC value; zUSDC minted @ 7 decimals on the Stellar side.
export const DENOMS = [
  { value: 1, label: "1 USDC" },
  { value: 10, label: "10 USDC" },
  { value: 100, label: "100 USDC" },
] as const;

export const etherscan = {
  address: (a: string) => `https://sepolia.etherscan.io/address/${a}`,
};

export const stellarExpert = {
  contract: (c: string) =>
    `https://stellar.expert/explorer/testnet/contract/${c}`,
};

/** middle-ellipsis a long on-chain identifier for display */
export function truncate(id: string, head = 6, tail = 4): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}
