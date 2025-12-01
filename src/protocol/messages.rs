use crate::crypto::merkle::ChunkedMerkleProof;
use crate::graph::Color;
use crate::stark::prover::BlankCountProof;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitments {
    pub graph_root: [u8; 32],
    pub permutation_root: [u8; 32],
    pub blank_root: [u8; 32],
    pub blank_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Challenge {
    Spot(SpotChallenge),
    Blank(BlankChallenge),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotChallenge {
    pub spots: Vec<[u32; 3]>,
    pub seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlankChallenge {
    pub edge_indices: Vec<u64>,
    pub seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotResponse {
    pub nodes: [u32; 3],
    pub edges: Vec<SpotEdgeOpening>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotEdgeOpening {
    pub from: u32,
    pub to: u32,
    pub color: Color,
    pub proof: ChunkedMerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotChallengeResponse {
    pub responses: Vec<SpotResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlankChallengeResponse {
    pub edges: Vec<BlankEdgeOpening>,
    pub stark_proof: BlankCountProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlankEdgeOpening {
    pub edge_index: u64,
    pub from: u32,
    pub to: u32,
    pub color: Color,
    pub is_blank: bool,
    pub color_proof: ChunkedMerkleProof,
    pub blank_proof: ChunkedMerkleProof,
}
