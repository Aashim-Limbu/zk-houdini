// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
import {IHasher} from "../src/IHasher.sol";
import {MerkleTreeWithHistory} from "../src/MerkleTreeWithHistory.sol";

contract MTHHarness is MerkleTreeWithHistory {
    constructor(uint32 levels, IHasher hasher, uint256 zeroValue)
        MerkleTreeWithHistory(levels, hasher, zeroValue)
    {}
    function insert(uint256 leaf) external returns (uint32) {
        return _insert(leaf);
    }
}

contract MerkleTreeWithHistoryTest is Test {
    using stdJson for string;

    MTHHarness tree;
    IHasher hasher;
    uint256 zeroValue;
    uint256 initialRoot;

    function setUp() public {
        string memory z = vm.readFile("test/vectors/zeros.json");
        zeroValue = uint256(z.readBytes32(".zeroValue"));
        initialRoot = uint256(z.readBytes32(".zeros[20]")); // root of empty depth-20 tree
        hasher = IHasher(address(new Poseidon2()));
        tree = new MTHHarness(20, hasher, zeroValue);
    }

    function test_InitialRootMatchesZerosTable() public view {
        assertEq(tree.getLastRoot(), initialRoot, "empty root mismatch");
        assertTrue(tree.isKnownRoot(initialRoot), "initial root should be known");
    }

    function test_InsertReturnsSequentialLeafIndex() public {
        assertEq(tree.insert(uint256(111)), 0, "first leaf index");
        assertEq(tree.insert(uint256(222)), 1, "second leaf index");
    }

    function test_InsertUpdatesRoot() public {
        uint256 beforeRoot = tree.getLastRoot();
        tree.insert(uint256(111));
        assertTrue(tree.getLastRoot() != beforeRoot, "root must change after insert");
        assertTrue(tree.isKnownRoot(tree.getLastRoot()), "new root must be known");
    }

    function test_OldRootStillKnownWithinWindow() public {
        uint256 r0 = tree.getLastRoot();
        tree.insert(uint256(111));
        assertTrue(tree.isKnownRoot(r0), "old root must remain known within 30-window");
    }

    function test_ZeroRootNeverKnown() public view {
        assertFalse(tree.isKnownRoot(0), "zero must never be a known root");
    }

    function test_RingBufferEvictsOldestRoot() public {
        // genesis root is roots[0]; after 30 inserts we wrap and overwrite roots[0].
        uint256 genesisRoot = tree.getLastRoot();
        for (uint256 i = 0; i < 30; i++) {
            tree.insert(uint256(1000 + i));
        }
        // After 30 inserts, currentRootIndex wrapped back to 0, overwriting genesis.
        assertFalse(tree.isKnownRoot(genesisRoot), "genesis root must be evicted after 30 inserts");
        assertTrue(tree.isKnownRoot(tree.getLastRoot()), "latest root still known");
    }

    /// Safety net for the hardcoded zeros: assert each equals the on-chain hasher's iterated compress.
    function test_HardcodedZerosMatchHasher() public view {
        uint256 z = 0;
        assertEq(tree.zeros(0), z, "zeros[0]");
        for (uint256 i = 1; i <= 20; i++) {
            z = hasher.compress(z, z);
            assertEq(tree.zeros(i), z, "hardcoded zeros mismatch vs hasher");
        }
    }
}
