use crate::crypto::hash::{default_quantum_hash, Blake3QuantumHash, QuantumHash};
use crate::crypto::merkle::ChunkedMerkleProof;
use crate::graph::{Color, ColorationSet, Spot};
use crate::protocol::messages::{
    BlankChallenge,
    BlankChallengeResponse,
    BlankEdgeOpening,
    Challenge,
    Commitments,
    SpotChallenge,
    SpotChallengeResponse,
};
use crate::stark::constraints::BlankCountConstraints;
use crate::stark::StarkField;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    pub rounds: u32,
    pub spots_per_round: u32,
    pub blank_checks_per_round: u32,
    pub spot_probability: f64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            rounds: 8,
            spots_per_round: 4,
            blank_checks_per_round: 2,
            spot_probability: 0.8,
        }
    }
}

pub struct Verifier {
    configuration: VerifierConfig,
    coloration_set: ColorationSet,
    commitments: Option<Commitments>,
    rng: StdRng,
    hasher: Blake3QuantumHash,
}

impl Verifier {
    pub fn new(coloration_set: ColorationSet, configuration: VerifierConfig) -> Self {
        Verifier {
            configuration,
            coloration_set,
            commitments: None,
            rng: StdRng::seed_from_u64(0xB10C_cafe),
            hasher: default_quantum_hash(),
        }
    }

    pub fn receive_commitments(&mut self, commitments: Commitments) {
        self.commitments = Some(commitments);
    }

    pub fn generate_challenge(&mut self, round: u32) -> Challenge {
        if self.rng.random::<f64>() < self.configuration.spot_probability {
            Challenge::Spot(self.generate_spot_challenge(round))
        } else {
            Challenge::Blank(self.generate_blank_challenge(round))
        }
    }

    fn generate_spot_challenge(&mut self, round: u32) -> SpotChallenge {
        let n = self.coloration_set.graph_size().max(3);
        let seed = self.challenge_seed(round, b"spot");
        let mut seeded_rng = StdRng::from_seed(seed);
        let mut spots = Vec::new();
        for _ in 0..self.configuration.spots_per_round {
            let mut nodes = [0u32; 3];
            let mut used = Vec::new();
            for idx in 0..3 {
                loop {
                    let candidate = seeded_rng.random_range(0..n);
                    if !used.contains(&candidate) {
                        nodes[idx] = candidate;
                        used.push(candidate);
                        break;
                    }
                }
            }
            spots.push(nodes);
        }
        SpotChallenge { spots, seed }
    }

    fn generate_blank_challenge(&mut self, round: u32) -> BlankChallenge {
        let n = self.coloration_set.graph_size().max(2) as u64;
        let seed = self.challenge_seed(round, b"blank");
        let mut seeded_rng = StdRng::from_seed(seed);
        let mut edge_indices = Vec::new();
        for _ in 0..self.configuration.blank_checks_per_round {
            edge_indices.push(seeded_rng.random_range(0..n * n));
        }
        BlankChallenge { edge_indices, seed }
    }

    fn challenge_seed(&self, round: u32, label: &[u8]) -> [u8; 32] {
        let commitments = self
            .commitments
            .as_ref()
            .expect("commitments must be set before generating challenges");
        let mut data = Vec::new();
        data.extend_from_slice(&commitments.graph_root);
        data.extend_from_slice(&commitments.permutation_root);
        data.extend_from_slice(&commitments.blank_root);
        data.extend_from_slice(&round.to_be_bytes());
        data.extend_from_slice(label);
        self.hasher.hash(&data)
    }

    pub fn verify_spot_response(
        &self,
        challenge: &SpotChallenge,
        response: &SpotChallengeResponse,
    ) -> bool {
        let commitments = match &self.commitments {
            Some(c) => c,
            None => return false,
        };
        if challenge.spots.len() != response.responses.len() {
                Self::debug_log("spot response rejected: response count mismatch");
            return false;
        }

        for (spot_nodes, resp) in challenge.spots.iter().zip(&response.responses) {
            if spot_nodes != &resp.nodes {
                    Self::debug_log("spot response rejected: node ordering mismatch");
                return false;
            }

            let mut edges = HashMap::new();
            for edge in &resp.edges {
                if !self.verify_graph_leaf(
                    edge.from,
                    edge.to,
                    edge.color,
                    &edge.proof,
                    &commitments.graph_root,
                ) {
                        Self::debug_log(&format!(
                        "spot response rejected: merkle proof mismatch for edge ({}, {})",
                        edge.from, edge.to
                    ));
                    return false;
                }
                edges.insert((edge.from, edge.to), edge.color);
            }

            let spot = Spot {
                nodes: resp.nodes,
                edges,
            };

            if !spot.is_valid(&self.coloration_set) {
                let mut details: Vec<String> = Vec::new();
                if env::var("ZKP_DEBUG_SPOT").is_ok() {
                    let mut entries: Vec<_> = spot.edges.iter().collect();
                    entries.sort_by_key(|(&(a, b), _)| (a, b));
                    for ((a, b), color) in entries {
                        details.push(format!("({},{})={:?}", a, b, color));
                    }
                }
                    Self::debug_log(&format!(
                    "spot response rejected: pattern not in coloration set for nodes {:?} -> {}",
                    spot.nodes,
                    details.join(", ")
                ));
                return false;
            }
        }
        true
    }

    fn debug_log(msg: &str) {
        if env::var("ZKP_DEBUG_SPOT").is_ok() {
            eprintln!("{}", msg);
        }
    }

    pub fn verify_blank_response(
        &self,
        challenge: &BlankChallenge,
        response: &BlankChallengeResponse,
    ) -> bool {
        let commitments = match &self.commitments {
            Some(c) => c,
            None => return false,
        };

        let openings_by_index: HashMap<u64, &BlankEdgeOpening> =
            response.edges.iter().map(|edge| (edge.edge_index, edge)).collect();

        for edge_idx in &challenge.edge_indices {
            let opening = match openings_by_index.get(edge_idx) {
                Some(opening) => opening,
                None => {
                    Self::debug_log(&format!(
                        "blank response rejected: missing opening for edge {}",
                        edge_idx
                    ));
                    return false;
                }
            };
            if !self.verify_graph_leaf(
                opening.from,
                opening.to,
                opening.color,
                &opening.color_proof,
                &commitments.graph_root,
            ) {
                Self::debug_log(&format!(
                    "blank response rejected: color proof mismatch for edge {}",
                    edge_idx
                ));
                return false;
            }
            if !self.verify_blank_opening(opening, &commitments.blank_root) {
                Self::debug_log(&format!(
                    "blank response rejected: blank proof mismatch for edge {}",
                    edge_idx
                ));
                return false;
            }
            if (opening.color == Color::Blank) != opening.is_blank {
                Self::debug_log(&format!(
                    "blank response rejected: blank flag mismatch for edge {}",
                    edge_idx
                ));
                return false;
            }
            let n = self.coloration_set.graph_size() as u64;
            if opening.edge_index >= n * n {
                Self::debug_log(&format!(
                    "blank response rejected: edge index {} out of bounds",
                    edge_idx
                ));
                return false;
            }
        }

        let constraints =
            BlankCountConstraints::<StarkField>::new(self.coloration_set.graph_size(), commitments.blank_count as u64);
        if !response.stark_proof.verify(&constraints, &self.hasher) {
            Self::debug_log("blank response rejected: STARK proof invalid");
            return false;
        }
        true
    }

    fn verify_graph_leaf(
        &self,
        from: u32,
        to: u32,
        color: Color,
        proof: &ChunkedMerkleProof,
        graph_root: &[u8; 32],
    ) -> bool {
        let leaf_bytes = encode_edge_leaf(from, to, color);
        let expected = self.hasher.hash(&leaf_bytes);
        if proof.leaf_proof.leaf_hash != expected {
            Self::debug_log(&format!(
                "leaf hash mismatch for edge ({}, {}): expected {:?}, proof {:?}, bytes {:?}",
                from,
                to,
                expected,
                proof.leaf_proof.leaf_hash,
                leaf_bytes
            ));
            return false;
        }
        if !proof.verify(graph_root, &self.hasher) {
            Self::debug_log(&format!(
                "merkle path mismatch for edge ({}, {})",
                from, to
            ));
            return false;
        }
        true
    }

    fn verify_blank_opening(
        &self,
        opening: &BlankEdgeOpening,
        blank_root: &[u8; 32],
    ) -> bool {
        let bit = if opening.is_blank { 1u8 } else { 0u8 };
        let leaf_bytes = vec![bit];
        if opening.blank_proof.leaf_proof.leaf_hash != self.hasher.hash(&leaf_bytes) {
            Self::debug_log("blank opening rejected: leaf hash mismatch");
            return false;
        }
        if !opening.blank_proof.verify(blank_root, &self.hasher) {
            Self::debug_log("blank opening rejected: merkle path mismatch");
            return false;
        }
        true
    }
}

fn encode_edge_leaf(from: u32, to: u32, color: Color) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(9);
    serialized.extend_from_slice(&from.to_be_bytes());
    serialized.extend_from_slice(&to.to_be_bytes());
    serialized.push(color.to_u8());
    serialized
}
