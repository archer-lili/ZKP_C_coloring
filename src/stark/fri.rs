use crate::crypto::hash::QuantumHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof {
    pub layer_roots: Vec<[u8; 32]>,
    pub query_positions: Vec<u64>,
}

pub fn derive_fri_layers(
    polynomial_size: usize,
    base_root: &[u8; 32],
    hasher: &dyn QuantumHash,
) -> Vec<[u8; 32]> {
    if polynomial_size <= 1 {
        return Vec::new();
    }

    let mut layers = Vec::new();
    let mut current = *base_root;
    let mut domain = polynomial_size.next_power_of_two().max(2);
    while domain > 1 {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&current);
        data.extend_from_slice(&(domain as u64).to_be_bytes());
        current = hasher.hash(&data);
        layers.push(current);
        domain /= 2;
    }
    layers
}

pub fn sample_fri_queries(
    polynomial_size: usize,
    base_root: &[u8; 32],
    num_queries: usize,
    hasher: &dyn QuantumHash,
) -> Vec<u64> {
    if polynomial_size == 0 || num_queries == 0 {
        return Vec::new();
    }

    let mut positions = Vec::new();
    let mut seed = *base_root;
    let mut counter = 0u64;
    while positions.len() < num_queries {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&seed);
        data.extend_from_slice(&counter.to_be_bytes());
        seed = hasher.hash(&data);
        let mut index_bytes = [0u8; 8];
        index_bytes.copy_from_slice(&seed[..8]);
        let candidate = u64::from_be_bytes(index_bytes) % (polynomial_size as u64);
        if !positions.contains(&candidate) {
            positions.push(candidate);
        }
        counter += 1;
    }
    positions.sort_unstable();
    positions
}
