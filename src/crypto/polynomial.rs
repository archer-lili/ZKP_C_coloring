use crate::crypto::hash::QuantumHash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct BlankPolynomial {
    values: Vec<u8>,
    prefix_sums: Vec<u64>,
}

impl BlankPolynomial {
    pub fn new(values: Vec<u8>) -> Self {
        let mut prefix_sums = Vec::with_capacity(values.len());
        let mut running = 0u64;
        for &value in &values {
            running += value as u64;
            prefix_sums.push(running);
        }

        BlankPolynomial {
            values,
            prefix_sums,
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn evaluate(&self, index: usize) -> u8 {
        self.values.get(index).copied().unwrap_or(0)
    }

    pub fn values(&self) -> &[u8] {
        &self.values
    }

    pub fn sum(&self) -> u64 {
        self.prefix_sums.last().copied().unwrap_or(0)
    }

    pub fn running_sum(&self, index: usize) -> u64 {
        self.prefix_sums.get(index).copied().unwrap_or(0)
    }

    pub fn commit(&self, hasher: &dyn QuantumHash) -> PolynomialCommitment {
        let mut bytes = Vec::with_capacity(self.values.len());
        bytes.extend_from_slice(&self.values);
        PolynomialCommitment {
            root: hasher.hash(&bytes),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolynomialCommitment {
    pub root: [u8; 32],
}
