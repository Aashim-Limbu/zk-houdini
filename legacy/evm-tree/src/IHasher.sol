// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Poseidon2 t=2 Merkle compression over BN254 Fr (fork PoseidonCompress = Permutation(2)).
///         Commitments (t=3 Poseidon2(2) sponge) are computed off-chain, not here.
interface IHasher {
    /// @return [o0, o1] of Perm2([l, r]).
    function perm(uint256 l, uint256 r) external pure returns (uint256, uint256);
    /// @notice Merkle compression: Compress(l,r) = Perm2([l,r])[0] + l (mod p).
    function compress(uint256 l, uint256 r) external pure returns (uint256);
}
