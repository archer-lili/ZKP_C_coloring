use blake3::Hasher as Blake3Hasher;
use sha3::{Digest, Sha3_512};

pub trait QuantumHash: Send + Sync {
    fn hash(&self, data: &[u8]) -> [u8; 32];

    fn hash_with_salt(&self, data: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(salt.len() + data.len());
        buf.extend_from_slice(salt);
        buf.extend_from_slice(data);
        self.hash(&buf)
    }
}

pub fn hash_chain(hasher: &dyn QuantumHash, seed: &[u8], rounds: usize) -> [u8; 32] {
    let mut current = hasher.hash(seed);
    if rounds == 0 {
        return current;
    }

    for counter in 0..rounds {
        let mut data = Vec::with_capacity(current.len() + 8);
        data.extend_from_slice(&current);
        data.extend_from_slice(&(counter as u64).to_be_bytes());
        current = hasher.hash(&data);
    }
    current
}

#[derive(Clone, Default)]
pub struct Blake3QuantumHash;

impl QuantumHash for Blake3QuantumHash {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[derive(Clone, Default)]
pub struct Sha3QuantumHash;

impl QuantumHash for Sha3QuantumHash {
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let result = hasher.finalize();
        result[..32].try_into().expect("sha3 output length")
    }
}

pub fn default_quantum_hash() -> Blake3QuantumHash {
    Blake3QuantumHash
}
