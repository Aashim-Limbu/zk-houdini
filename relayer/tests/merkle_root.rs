use relayer::merkle::MerkleTree;
use relayer::poseidon::{hash2, to_hex, Fr};

#[test]
fn path_recomputes_root() {
    let mut tree = MerkleTree::new(20);
    let leaves: Vec<Fr> = (1u64..=5).map(Fr::from).collect();
    for l in &leaves { tree.insert(*l); }
    let root = tree.root();
    for (i, leaf) in leaves.iter().enumerate() {
        let (pe, pi) = tree.proof(i);
        assert_eq!(MerkleTree::recompute_root(*leaf, &pe, &pi), root, "leaf {i} path must recompute root");
    }
}

#[test]
fn single_leaf_root_matches_circuit_witness() {
    // commitment of (nullifier=12345, secret=67890) at index 0 — must equal gen_input.py root.
    let mut tree = MerkleTree::new(20);
    tree.insert(hash2(Fr::from(12345u64), Fr::from(67890u64)));
    assert_eq!(to_hex(&tree.root()),
        "0x0012f4149c6840973c2dee91e8ecd7dd2839be83b143607114e7b4cd70bd86d4",
        "relayer single-leaf root must match the circuit witness root");
}

#[test]
fn empty_tree_root_deterministic() {
    assert_eq!(to_hex(&MerkleTree::new(20).root()), to_hex(&MerkleTree::new(20).root()));
}
