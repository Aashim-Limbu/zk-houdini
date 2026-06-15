//! Off-chain Merkle tree (depth-parametrized) using the keystone t=2 `compress`.
//! Mirrors the EVM tree + circuit: node(l,r)=compress(l,r), empty leaf = 0,
//! pathIndices[i]=0 => current is LEFT child (sibling right).
use crate::poseidon::{compress, Fr};

pub struct MerkleTree {
    pub depth: usize,
    zeros: Vec<Fr>,
    leaves: Vec<Fr>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zeros = Vec::with_capacity(depth + 1);
        zeros.push(Fr::from(0u64));
        for i in 1..=depth {
            zeros.push(compress(zeros[i - 1], zeros[i - 1]));
        }
        MerkleTree { depth, zeros, leaves: Vec::new() }
    }

    pub fn insert(&mut self, leaf: Fr) -> usize {
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    fn layers(&self) -> Vec<Vec<Fr>> {
        let mut layers: Vec<Vec<Fr>> = Vec::with_capacity(self.depth + 1);
        layers.push(self.leaves.clone());
        for level in 0..self.depth {
            let cur = &layers[level];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() { cur[i + 1] } else { self.zeros[level] };
                next.push(compress(left, right));
                i += 2;
            }
            if next.is_empty() {
                next.push(self.zeros[level + 1]);
            }
            layers.push(next);
        }
        layers
    }

    pub fn root(&self) -> Fr {
        if self.leaves.is_empty() {
            return self.zeros[self.depth];
        }
        self.layers()[self.depth][0]
    }

    /// (pathElements[depth], pathIndices[depth]) for the leaf at `index`.
    pub fn proof(&self, index: usize) -> (Vec<Fr>, Vec<u8>) {
        let layers = self.layers();
        let mut pe = Vec::with_capacity(self.depth);
        let mut pi = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let cur = &layers[level];
            let is_right = idx % 2 == 1;
            let sib_idx = if is_right { idx - 1 } else { idx + 1 };
            let sib = if sib_idx < cur.len() { cur[sib_idx] } else { self.zeros[level] };
            pe.push(sib);
            pi.push(if is_right { 1u8 } else { 0u8 });
            idx /= 2;
        }
        (pe, pi)
    }

    pub fn recompute_root(leaf: Fr, pe: &[Fr], pi: &[u8]) -> Fr {
        let mut cur = leaf;
        for (sib, bit) in pe.iter().zip(pi.iter()) {
            cur = if *bit == 0 { compress(cur, *sib) } else { compress(*sib, cur) };
        }
        cur
    }
}
