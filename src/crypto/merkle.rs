use crate::crypto::hash::QuantumHash;
use crate::graph::Graph;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::env;

const DEFAULT_CHUNK_SIZE: usize = 1024;
const DEFAULT_CACHE_SIZE: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    pub path: Vec<([u8; 32], bool)>,
}

impl MerkleProof {
    pub fn verify(&self, root: &[u8; 32], hasher: &dyn QuantumHash) -> bool {
        let mut current = self.leaf_hash;
        for (sibling, is_right) in &self.path {
            let mut data = Vec::with_capacity(64);
            if *is_right {
                data.extend_from_slice(&current);
                data.extend_from_slice(sibling);
            } else {
                data.extend_from_slice(sibling);
                data.extend_from_slice(&current);
            }
            current = hasher.hash(&data);
        }
        &current == root
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn new(data: &[Vec<u8>], hasher: &dyn QuantumHash) -> Self {
        let mut current: Vec<[u8; 32]> = data.iter().map(|leaf| hasher.hash(leaf)).collect();
        if current.is_empty() {
            current.push(hasher.hash(&[]));
        }

        let mut levels = vec![current.clone()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity((prev.len() + 1) / 2);
            for chunk in prev.chunks(2) {
                if chunk.len() == 2 {
                    let mut buf = Vec::with_capacity(64);
                    buf.extend_from_slice(&chunk[0]);
                    buf.extend_from_slice(&chunk[1]);
                    next.push(hasher.hash(&buf));
                } else {
                    next.push(chunk[0]);
                }
            }
            levels.push(next);
        }

        MerkleTree { levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|lvl| lvl.len()).unwrap_or(0)
    }

    pub fn get_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.levels.first()?.len() {
            return None;
        }

        let mut proof_path = Vec::new();
        let mut idx = index;
        for level in &self.levels {
            if level.len() == 1 {
                break;
            }
            let sibling = idx ^ 1;
            if sibling < level.len() {
                let sibling_hash = level[sibling];
                let is_right = sibling > idx;
                proof_path.push((sibling_hash, is_right));
            }
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_index: index as u64,
            leaf_hash: self.levels[0][index],
            path: proof_path,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedMerkleProof {
    pub chunk_index: u64,
    pub leaf_index_within_chunk: u64,
    pub leaf_proof: MerkleProof,
    pub chunk_proof: MerkleProof,
}

impl ChunkedMerkleProof {
    pub fn verify(&self, root: &[u8; 32], hasher: &dyn QuantumHash) -> bool {
        let chunk_root = compute_merkle_root(&self.leaf_proof, hasher);
        let expected_chunk_leaf = hasher.hash(chunk_root.as_slice());
        if self.chunk_proof.leaf_hash != expected_chunk_leaf {
            debug_merkle("chunk leaf hash mismatch");
            return false;
        }
        if !self.chunk_proof.verify(root, hasher) {
            debug_merkle("chunk proof path mismatch");
            return false;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct ChunkedMerkleTree {
    chunk_size: usize,
    chunk_trees: Vec<MerkleTree>,
    top_tree: MerkleTree,
    leaf_count: usize,
    cache: RefCell<HashMap<usize, ChunkedMerkleProof>>,
    cache_order: RefCell<VecDeque<usize>>,
    cache_capacity: usize,
}

impl ChunkedMerkleTree {
    pub fn new(data: &[Vec<u8>], hasher: &dyn QuantumHash, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.max(1);
        let cache_capacity = DEFAULT_CACHE_SIZE;

        if data.is_empty() {
            let empty_tree = MerkleTree::new(&[Vec::new()], hasher);
            return ChunkedMerkleTree {
                chunk_size,
                chunk_trees: vec![empty_tree.clone()],
                top_tree: empty_tree,
                leaf_count: 0,
                cache: RefCell::new(HashMap::new()),
                cache_order: RefCell::new(VecDeque::new()),
                cache_capacity,
            };
        }

        let mut chunk_roots = Vec::new();
        let mut chunk_trees = Vec::new();
        for chunk in data.chunks(chunk_size) {
            let tree = MerkleTree::new(chunk, hasher);
            chunk_roots.push(tree.root());
            chunk_trees.push(tree);
        }

        let top_leaves: Vec<Vec<u8>> = chunk_roots
            .iter()
            .map(|root| root.to_vec())
            .collect();
        let top_tree = MerkleTree::new(&top_leaves, hasher);

        ChunkedMerkleTree {
            chunk_size,
            chunk_trees,
            top_tree,
            leaf_count: data.len(),
            cache: RefCell::new(HashMap::new()),
            cache_order: RefCell::new(VecDeque::new()),
            cache_capacity,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.top_tree.root()
    }

    pub fn leaves(&self) -> usize {
        self.leaf_count
    }

    pub fn get_proof(&self, index: usize) -> Option<ChunkedMerkleProof> {
        if index >= self.leaf_count {
            return None;
        }

        if let Some(proof) = self.cache.borrow().get(&index) {
            return Some(proof.clone());
        }

        let chunk_index = index / self.chunk_size;
        let offset = index % self.chunk_size;
        let leaf_tree = self.chunk_trees.get(chunk_index)?;
        let leaf_proof = leaf_tree.get_proof(offset)?;
        let chunk_proof = self.top_tree.get_proof(chunk_index)?;

        let proof = ChunkedMerkleProof {
            chunk_index: chunk_index as u64,
            leaf_index_within_chunk: offset as u64,
            leaf_proof,
            chunk_proof,
        };
        self.insert_cache(index, proof.clone());
        Some(proof)
    }

    fn insert_cache(&self, index: usize, proof: ChunkedMerkleProof) {
        let mut cache = self.cache.borrow_mut();
        let mut order = self.cache_order.borrow_mut();
        if cache.contains_key(&index) {
            return;
        }
        cache.insert(index, proof);
        order.push_back(index);
        if cache.len() > self.cache_capacity {
            if let Some(oldest) = order.pop_front() {
                cache.remove(&oldest);
            }
        }
    }
}

fn debug_merkle(msg: &str) {
    if env::var("ZKP_DEBUG_SPOT").is_ok() {
        eprintln!("{}", msg);
    }
}

fn compute_merkle_root(proof: &MerkleProof, hasher: &dyn QuantumHash) -> [u8; 32] {
    let mut current = proof.leaf_hash;
    for (sibling, is_right) in &proof.path {
        let mut data = Vec::with_capacity(64);
        if *is_right {
            data.extend_from_slice(&current);
            data.extend_from_slice(sibling);
        } else {
            data.extend_from_slice(sibling);
            data.extend_from_slice(&current);
        }
        current = hasher.hash(&data);
    }
    current
}

#[derive(Debug, Clone)]
pub struct GraphMerkleTree {
    chunked: ChunkedMerkleTree,
    edge_to_index: HashMap<(u32, u32), usize>,
}

impl GraphMerkleTree {
    pub fn from_graph(graph: &Graph, hasher: &dyn QuantumHash) -> Self {
        let mut data = Vec::with_capacity((graph.n as usize).pow(2));
        let mut edge_to_index = HashMap::new();
        let mut idx = 0;

        for i in 0..graph.n {
            for j in 0..graph.n {
                let color = graph.get_edge(i, j);
                let mut serialized = Vec::with_capacity(9);
                serialized.extend_from_slice(&i.to_be_bytes());
                serialized.extend_from_slice(&j.to_be_bytes());
                serialized.push(color.to_u8());
                data.push(serialized);
                edge_to_index.insert((i, j), idx);
                idx += 1;
            }
        }

        let chunked = ChunkedMerkleTree::new(&data, hasher, DEFAULT_CHUNK_SIZE);

        GraphMerkleTree {
            chunked,
            edge_to_index,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.chunked.root()
    }

    pub fn get_edge_proof(&self, from: u32, to: u32) -> Option<ChunkedMerkleProof> {
        let index = *self.edge_to_index.get(&(from, to))?;
        self.chunked.get_proof(index)
    }
}
